#!/usr/bin/env python

import dns.resolver
import http.server
import json

# http endpoint for e2e monitoring of dnssync operation
# it queries public nameservers in order to check if they return the same IP
# addresses as the corresponding loadbalancer entries.
# It should be queried with a json request body specifying a set of
# loadbalancers FQDNs with the domans that should resolve to the same IP's
# For example
# {
#  "lb-id1.lb.appdomain.cloud": [
#     "app-prd-1.example.net",
#     "app-prd-2.example.net",
#  ],
#  "lib-id2.lb.appdomain.cloud": [
#     "app-tst-1.example.net"
#  ]
#}


class Monitor(http.server.BaseHTTPRequestHandler):

    resolver = dns.resolver.Resolver(configure=False)
    resolver.cache = dns.resolver.Cache()
    resolver.nameservers = (['8.8.8.8', '8.8.4.4'])

    def get_rds(self, host):
        return self.resolver.resolve(host).rrset.to_rdataset()

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        try:
            content_len = self.headers.get('Content-Length')
            lbs = json.loads(self.rfile.read(int(content_len)))
        except Exception:
            # Bad request: request body missing or json parse error
            self.send_error(400)
            return
        # Iterate over domains and record the result of the comparison in an
        # array
        result = []
        for lb, domains in lbs.items():
            result += [self.get_rds(lb) == self.get_rds(d) for d in domains]
        self.send_response(200 if all(result) else 404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        res = iter(result)
        # Summarize the result in the response body
        for lb, domains in lbs.items():
            for d in domains:
                if next(res):
                    self.wfile.write((f'OK: {d}\n'.encode()))
                else:
                    self.wfile.write(f'ERROR: {d}\n'.encode())
