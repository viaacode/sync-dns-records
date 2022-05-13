import re
import configparser

class Config:

    def __init__(self, filename):
        self.config = configparser.ConfigParser()
        self.config.read(filename)
        self.remote_dns = self.config['DEFAULT']['RemoteDnsServers'].split()
        print(self.remote_dns)
        self.set_loadbalancers()

    def set_loadbalancers(self):
        loadbalancers = {}
        for domain in self.config:
            if re.search('[a-zA-Z0-9-]\.[a-zA-Z0-9-]', domain):
                zone = self.config[domain]['zone']
                lb = self.config[domain]['loadbalancer']
                if not loadbalancers.get(lb):
                    loadbalancers[lb] = []
                loadbalancers[lb].append({'fqdn': domain, 'zone': zone})
        self.loadbalancers = loadbalancers
        print(loadbalancers)

