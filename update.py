#!/usr/bin/env python

import dns.query
import dns.message
import dns.tsigkeyring
import dns.update
import time
import re
import traceback
import datetime
import threading
import logging
import configparser;

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] (%(threadName)s): %(message)s')

config = configparser.ConfigParser()
config.read('update.ini')
RemoteDnsServers = config['DEFAULT']['RemoteDnsServers'].split(',')
print(RemoteDnsServers)
loadbalancers = {}
for domain in [ dm for dm in config.keys() if re.search('\w\.\w', dm) ]:
  zone = config[domain]['zone']
  lb = config[domain]['loadbalancer']
  if not loadbalancers.get(lb): loadbalancers[lb] = []
  loadbalancers[lb].append({'fqdn': domain, 'zone': zone})
print(loadbalancers)


# Bind generates a local TSIG key in /var/run/named/session.key if any local
# primary zone has set update-policy to local. We extract the TSIG key form this file
# just before and every time we need it.
# This file is formatted as follows: 
# key "local-ddns" {
#	algorithm hmac-sha256;
#	secret "base64 encoded secret";
# };
def get_keyring():
    with open('/var/run/named/session.key','r') as keyfile:
        for line in keyfile:
            match = re.search('^\s*key\s*"([^"]+)"\s*{', line)
            if match:
                key_name = match.group(1)
            match = re.search('secret\s*"([^"]*)"\s*;\s*', line)
            if match:
                key_secret = match.group(1)
        return dns.tsigkeyring.from_text( {key_name: key_secret} )

# Check if we have a valid response
def valid(response, name):
    answer = response.answer
    if ( answer and # There is an answer section
            len(answer) == 1 and  # It contains exactly one rrset
            answer[0].name.to_text() == f'{name}.' and # It is an answer for name
            len(answer[0]) >= 1 and # We have at least one RR in our rrset
            # We have nothing but A records
            all([ x.rdtype == dns.rdatatype.A for x in answer ]) ):
        logging.debug(f'valid response: {answer}')
        return True
    else:
        logging.debug(f'invalid response for {name}.') 
        logging.debug(response.to_text())
        return False

def query_ibm(hostname):
    q_ibm = dns.message.make_query(hostname, 'A')
    response = None
    for server in RemoteDnsServers:
        try:
            logging.debug(f'query {server}')
            r_ibm = dns.query.udp(q_ibm, server, timeout=5)
            if valid(r_ibm, hostname):
               response = r_ibm.answer[0].to_rdataset()
               break
        except:
            traceback.print_exc()
            time.sleep(5)
    return response

class TstDns:

    def rcode(self):
        return dns.rcode.NOTIMP

loacl_dns_lock = threading.Lock()
def update_local_dns(zone, name, rdataset):
    update = dns.update.UpdateMessage(f'{zone}.', keyring=get_keyring())
    update.replace(f'{name}.', rdataset)
    with loacl_dns_lock:
        resp = dns.query.udp(update, '127.0.0.1')
    return resp.rcode()


def track(lb, domains):
  while True:
    ibm_a_records = query_ibm(lb)
    if ibm_a_records:
      for domain in domains:
        q_local = dns.message.make_query(f'{domain["fqdn"]}.', 'A')
        try:
          r_local = dns.query.udp(q_local, '127.0.0.1', timeout=3)
          if not r_local.answer or (r_local.answer[0].to_rdataset() != ibm_a_records):
              logging.info(f'Replacing: {r_local.answer} by {[ ibm_a_records]}')
              result = update_local_dns(domain["zone"], domain["fqdn"], ibm_a_records)
              logging.debug(f'Replacing <{domain["fqdn"]}>: {dns.rcode.to_text(result)}')
          else:
              logging.info(f'Equal: {r_local.answer}')
        except:
            traceback.print_exc()
      t = ibm_a_records.ttl + 1
    else:
      t = 30 
    logging.debug(f'sleeping {t} seonds')
    time.sleep(t) 

threads = []
for loadbalancer in loadbalancers.keys():
    threads.append(threading.Thread(target=track, args=(loadbalancer, loadbalancers[loadbalancer]), name = loadbalancer))

for thread in threads:
    logging.debug(f'Starting thread {thread.name}')
    thread.start()


