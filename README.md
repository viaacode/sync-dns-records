# sync-dns-records

Tracks and synchronises A records from one DNS zone to another.

Setting up domain name aliases is usually achieved using CNAME records.
However, CNAME record restrictions make this impossible in certain cases, for
example when other data (SOA, MX, NS records) is present at the alias node.

This tool queries given A records from one (canonical) zone and updates
corresponding A records in another (alias) zone. It is designed to run on a
machine/container running [bind](https://www.isc.org/bind/) as primary dns
server for the alias zone. It is assumed that the machine/container is not
exposed to the internet (hence bind replicates to public secundary dns
servers). It could also be used to update a remote bind server, but this would
have additional security implications.

## Use case

Our use case is exposing apps using public loadbalancers in the IBM cloud.  The
IP addresses of these loadbalancers are dynamic and published as A records with
a TTL of a few minutes on the loadbalancers domain name. The IBM recommended
way of working is to use a CNAME alias for the app's domain name, but this
is not possible for all our apps due to CNAME limitations.

## Monitoring

An HTTP endpoint is included that compares A records of the loadbalancer with
those of the alias domains using public DNS servers.

## Usage

A systemd unit file is included that runs the script as bind user.
It uses the default security mechanism provided by bind for zones with
update-policy = local.

## Dependencies

[dnspython](https://www.dnspython.org)
