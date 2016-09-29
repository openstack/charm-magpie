# Overview

Magpie is a charm used for testing networking (ICMP and DNS specifically)
on a provider/substrate. Simply deploy more than one Magpie charm and 
watch the status messages. 

Status messages will show the unit numbers that have issues - if there are 
no problems, there will not be a verbose status message.

All actions, strings, queries and actions are logged in the juju logs.

# Usage

```
juju deploy magpie -n 2
juju deploy magpie -n 1 --to lxc:1
```

This charm also supports the following config values:

```yaml
  dns_server:
    default: ''
    description: Use unit default DNS server 
    type: string
  dns_tries:
    default: 1
    description: Number of DNS resolution attempts per query
    type: int
  dns_time:
    default: 3
    description: Timeout in seconds per DNS query try
    type: int
  ping_timeout:
    default: 2
    description: Timeout in seconds per ICMP request
    type: int
  ping_tries:
    default: 1
    description: Number of ICMP packets per ping
    type: int
```

e.g.

juju set magpie dns_server=8.8.8.8
