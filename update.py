#!/usr/bin/env python

import dns.query
import dns.message
import dns.tsigkeyring
import dns.update
import dns.resolver
import time
import re
import traceback
import threading
import logging
import configparser
import http.server

logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] (%(threadName)s): %(message)s')

config = configparser.ConfigParser()
config.read('update.ini')
RemoteDnsServers = config['DEFAULT']['RemoteDnsServers'].split(',')
print(RemoteDnsServers)
loadbalancers = {}
domainnames = [d for d in config if re.search('[a-zA-Z0-9-]\.[a-zA-Z0-9-]', d)]

class Monitor(http.server.BaseHTTPRequestHandler):

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = (['8.8.8.8', '8.8.4.4'])

    def get_rds(self, host):
        return self.resolver.resolve(host).rrset.to_rdataset()

    def do_GET(self):
        result = [self.get_rds(d) == self.get_rds(config[d]['loadbalancer']) for d in domainnames]
        self.send_response(200 if all(result) else 404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        for i,d in enumerate(domainnames):
            if result[i]:
                self.wfile.write((f'OK: {config[d].name}\n'.encode()))
            else:
                self.wfile.write(f'ERROR: {config[d].name}\n'.encode())

for domain in domainnames:
    zone = config[domain]['zone']
    lb = config[domain]['loadbalancer']
    if not loadbalancers.get(lb):
        loadbalancers[lb] = []
    loadbalancers[lb].append({'fqdn': domain, 'zone': zone})
print(loadbalancers)


#
# Bind generates a local TSIG key in /var/run/named/session.key if any local
# primary zone has set update-policy to local. We extract the TSIG key from
# this file
# The file is formatted as follows:
# key "local-ddns" {
#	algorithm hmac-sha256;
#	secret "base64 encoded secret";
# };
def get_keyring():
    with open('/var/run/named/session.key', 'r') as keyfile:
        for line in keyfile:
            match = re.search('^\s*key\s*"([^"]+)"\s*{', line)
            if match:
                key_name = match.group(1)
            match = re.search('secret\s*"([^"]*)"\s*;\s*', line)
            if match:
                key_secret = match.group(1)
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
    for server in RemoteDnsServers:
        try:
            logging.debug(f'query {server}')
            r_remote = dns.query.udp(q_remote, server, timeout=5)
            if valid(r_remote, hostname):
                response = r_remote.answer[0].to_rdataset()
                break
        except Exception:   # We reaaly want to catch all exceptions here
            traceback.print_exc()
            time.sleep(5)
    return response


class TstDns:

    def rcode(self):
        return dns.rcode.NOTIMP


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
    return r_local.answer[0].to_rdataset() == remote_a_records if r_local.answer else false


def track(lb, domains):
    while True:
        remote_a_records = query_remote(lb)
        if remote_a_records:
            for domain in domains:
              try:
                if not local_dns_insync(domain['fqdn'], remote_a_records):
                    logging.info(f'Replacing: local records by {[ remote_a_records]}')
                    result = update_local_dns(domain["zone"], domain["fqdn"], remote_a_records)
                    logging.debug(f'Replacing <{domain["fqdn"]}>: {dns.rcode.to_text(result)}')
                else:
                    logging.info(f'{domain["fqdn"]}: Equal!')
              except Exception:
                  traceback.print_exc()
            t = remote_a_records.ttl + 1
        else:
            t = 30
        logging.debug(f'sleeping {t} seonds')
        time.sleep(t)


local_dns_lock = threading.Lock()
threads = []
for loadbalancer in loadbalancers.keys():
    threads.append(threading.Thread(target=track,
        args=(loadbalancer, loadbalancers[loadbalancer]), name=loadbalancer))

for thread in threads:
    logging.debug(f'Starting thread {thread.name}')
    thread.start()

httpd = http.server.HTTPServer(('',8080), Monitor)
httpd.serve_forever()
