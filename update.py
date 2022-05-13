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

cfg = Config('update.ini')


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


# Check if we have a valid response
def valid(response, name):
    answer = response.answer
    if (answer and  # There is an answer section
            len(answer) == 1 and  # It contains exactly one rrset
                answer[0].name.to_text() == f'{name}.' and  # It is an answer for name
                len(answer[0]) >= 1 and  # We have at least one RR in our rrset
                # We have nothing but A records
                all([x.rdtype == dns.rdatatype.A for x in answer])):
        logging.debug(f'valid response: {answer}')
        return True
    else:
        logging.debug(f'invalid response for {name}.')
        logging.debug(response.to_text())
        return False


def query_remote(hostname):
    q_remote = dns.message.make_query(hostname, 'A')
    response = None
    servers = iter(cfg.remote_dns)
    while response is None:
        try:
            server = next(servers)
            logging.debug(f'query {server}')
            r_remote = dns.query.udp(q_remote, server, timeout=5)
            if valid(r_remote, hostname):
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


def local_dns_insync(fqdn, remote_a_records):
    q_local = dns.message.make_query(f'{fqdn}.', 'A')
    r_local = dns.query.udp(q_local, '127.0.0.1', timeout=3)
    logging.info(f'Local response: {r_local.answer}')
    return r_local.answer[0].to_rdataset() == remote_a_records if r_local.answer else False


def track_domain(domain, remote_a_records):
    try:
        if not local_dns_insync(domain['fqdn'], remote_a_records):
            logging.info(f'Replacing: local records by {[ remote_a_records]}')
            result = update_local_dns(domain["zone"],
                    domain["fqdn"], remote_a_records)
            logging.debug(f'Replacing <{domain["fqdn"]}>: {dns.rcode.to_text(result)}')
        else:
            logging.info(f'{domain["fqdn"]}: Equal!')
    except Exception:
        traceback.print_exc()


def track(lb, domains):
    while True:
        remote_a_records = query_remote(lb)
        if remote_a_records:
            for domain in domains:
                track_domain(domain, remote_a_records)
                t = remote_a_records.ttl + 1
        else:
            t = 30
        logging.debug(f'sleeping {t} seonds')
        time.sleep(t)


local_dns_lock = threading.Lock()
threads = []
for loadbalancer in cfg.loadbalancers.keys():
    threads.append(threading.Thread(target=track,
        args=(loadbalancer, cfg.loadbalancers[loadbalancer]), name=loadbalancer))

for thread in threads:
    logging.debug(f'Starting thread {thread.name}')
    thread.start()

httpd = http.server.HTTPServer(('', 8080), Monitor)
httpd.serve_forever()
