#!/usr/bin/env python

import dns.resolver
import http.server
import json


class Monitor(http.server.BaseHTTPRequestHandler):

    resolver = dns.resolver.Resolver(configure=False)
    resolver.cache = dns.resolver.Cache()
    resolver.nameservers = (['8.8.8.8', '8.8.4.4'])

    def get_rds(self, host):
        return self.resolver.resolve(host).rrset.to_rdataset()

    #def do_POST(self):
    #    do_GET(self)

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length')) if self.headers.get('Content-Length') else 0
        lbs = json.loads(self.rfile.read(content_len))
        result = []
        for lb, domains in lbs.items():
           result += [self.get_rds(lb) == self.get_rds(d) for d in domains]
        self.send_response(200 if all(result) else 404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        res = iter(result)
        for lb, domains in lbs.items():
            for d in domains:
                if next(res):
                    self.wfile.write((f'OK: {d}\n'.encode()))
                else:
                    self.wfile.write(f'ERROR: {d}\n'.encode())

