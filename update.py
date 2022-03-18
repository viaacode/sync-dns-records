#!/usr/bin/env python

import dns.query
import dns.message
import dns.tsigkeyring
import dns.update
import time
import re
import traceback
import datetime


domains = [
        {
            'fqdn': 'onderwijs.hetarchief.be',
            'zone': 'hetarchief.be',
            'lbhostname': '8c77acda-eu-de.lb.appdomain.cloud'
            }
        ]

ttl = 120

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
        log('valid response:', answer)
        return True
    else:
        log(f'nvalid response for {name}.') 
        log(response.to_text())
        return False

def query_ibm(hostname):
    DnsServers = [ '162.159.42.2', '162.159.34.3', '10.50.24.30', '10.50.24.31' ]
    q_ibm = dns.message.make_query(hostname, 'A')
    response = None
    for server in DnsServers:
        try:
            log(f'query {server}')
            r_ibm = dns.query.udp(q_ibm, server, timeout=5)
            if valid(r_ibm, hostname):
               response = r_ibm.answer[0].to_rdataset()
               break
        except:
            traceback.print_exc()
            time.sleep(5)
    return response

def update_local_dns(zone, name, rdataset):
    update = dns.update.UpdateMessage(f'{zone}.', keyring=get_keyring())
    update.replace(f'{name}.', rdataset)
    resp = dns.query.udp(update, '127.0.0.1')
    log(dns.rcode.to_text(resp.rcode()))
    return resp.rcode()

def log(*strings):
    print(str(datetime.datetime.now()), *strings)

while True:
    for domain in domains:
        ibm_a_records = query_ibm(domain['lbhostname'])
        if not ibm_a_records: continue # See you next time
        ttl = ibm_a_records.ttl
        q_meemoo = dns.message.make_query(f'{domain["fqdn"]}.', 'A')
        try:
          r_meemoo = dns.query.udp(q_meemoo, '127.0.0.1', timeout=3)
          if not r_meemoo.answer or (r_meemoo.answer[0].to_rdataset() != ibm_a_records):
            log('Replacing:', r_meemoo.answer)
            update_local_dns(domain["zone"], domain["fqdn"], ibm_a_records)
          else:
              log('equal:', r_meemoo.answer)
        except:
            traceback.print_exc()
    time.sleep(ttl + 1) 
