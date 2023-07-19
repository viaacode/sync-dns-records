#!/usr/bin/env python

import dns.query
import dns.message
import dns.tsigkeyring
import dns.update
import time
import re
import traceback
import threading
import logging
import http.server
from monitor import Monitor
from config import Config

logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] (%(threadName)s): %(message)s')

# Build a dictionary loadbalancers with the domains and zones to be
# synchronised:
# {'loadbalancer-fqdn': [ {'fqdn': 'app.domain.net', 'zone': 'domain.net'} ]
cfg = Config('update.ini')
logging.debug(f'Remote DNS servers: {cfg.remote_dns}')
logging.debug(f'Loadbalancers: {cfg.loadbalancers}')


# Bind generates a local TSIG key in /var/run/named/session.key if any local
# primary zone has set update-policy to local. We extract the TSIG key from
# this file which is formatted as follows:
# key "local-ddns" {
#       algorithm hmac-sha256;
#       secret "base64 encoded secret";
# };
def get_keyring():
    with open('/var/run/named/session.key', 'r') as keyfile:
        key_name = key_secret = ''
        for line in keyfile:
            match = re.search('^\s*key\s*"([^"]+)"\s*{', line)
            if match:
                key_name = match.group(1)
            match = re.search('secret\s*"([^"]*)"\s*;\s*', line)
            if key_name and match:
                key_secret = match.group(1)
                break
    if not key_secret:
        raise RuntimeError('Load tsig key')
    return dns.tsigkeyring.from_text({key_name: key_secret})


# Do some sanity checks on a response.
# - there must be an answer section
# - The answer must contain exactly one rrset
# - It must be an answer for the given name
# - It must contain exactly one rr
# - The rr must only contain A records
def is_valid(response, name):
    answer = response.answer
    if (answer and
            len(answer) == 1 and
                answer[0].name.to_text() == f'{name}.' and
                len(answer[0]) >= 1 and
                all([x.rdtype == dns.rdatatype.A for x in answer])):
        logging.debug(f'valid response: {answer}')
        return True
    else:
        logging.debug(f'invalid response for {name}.')
        logging.debug(response.to_text())
        return False


def query_remote_dns(hostname):
    q_remote = dns.message.make_query(hostname, 'A')
    response = None
    servers = iter(cfg.remote_dns)
    # Loop over the remote DNS servers untill we have a valid response
    while response is None:
        try:
            server = next(servers)
            logging.debug(f'query {server}')
            r_remote = dns.query.udp(q_remote, server, timeout=5)
            if is_valid(r_remote, hostname):
                response = r_remote.answer[0].to_rdataset()
        except StopIteration:
            break
        except Exception:  # We reaaly want to catch all other exceptions here
            traceback.print_exc()
            time.sleep(5)
    return response


def update_local_dns(zone, name, rdataset):
    update = dns.update.UpdateMessage(f'{zone}.', keyring=get_keyring())
    update.replace(f'{name}.', rdataset)
    with local_dns_lock:
        resp = dns.query.udp(update, '127.0.0.1')
    return resp.rcode()


def is_local_dns_insync(fqdn, remote_a_records):
    q_local = dns.message.make_query(f'{fqdn}.', 'A')
    r_local = dns.query.udp(q_local, '127.0.0.1', timeout=3)
    logging.info(f'Local response: {r_local.answer}')
    return r_local.answer[0].to_rdataset() == remote_a_records if r_local.answer else False


def sync_domain(domain, remote_a_records):
    try:
        if not is_local_dns_insync(domain['fqdn'], remote_a_records):
            logging.info(f'Replacing: local records by {[ remote_a_records]}')
            result = update_local_dns(domain["zone"],
                    domain["fqdn"], remote_a_records)
            logging.debug(f'Replacing <{domain["fqdn"]}>: {dns.rcode.to_text(result)}')
        else:
            logging.info(f'{domain["fqdn"]}: Equal!')
    except Exception:
        traceback.print_exc()


# Entrypoint for the thread that tracks a loadbalancer's domains
# check interval is given by the remote DNS record TTL
def track(lb, domains):
    while True:
        remote_a_records = query_remote_dns(lb)
        if remote_a_records:
            for domain in domains:
                sync_domain(domain, remote_a_records)
                t = remote_a_records.ttl + 1
        else:
            t = 30
        logging.debug(f'sleeping {t} seonds')
        time.sleep(t)


local_dns_lock = threading.Lock()
threads = [
    threading.Thread(target=track, args=(lb, cfg.loadbalancers[lb]), name=lb)
    for lb in cfg.loadbalancers.keys()
    ]

for thread in threads:
    logging.debug(f'Starting thread {thread.name}')
    thread.start()

# Start http server for monitoring
httpd = http.server.HTTPServer(('', 8080), Monitor)
httpd.serve_forever()
