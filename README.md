# Overview

Magpie is a charm used for testing the networking (ICMP and DNS specifically)
of a juju provider/substrate. Simply deploy more than one Magpie charm and 
watch the status messages and debug logs. 

Status messages will show the unit numbers that have issues - if there are 
no problems, there will not be a verbose status message.

All actions, strings, queries and actions are logged in the juju logs.


# Workload Status

In addition to ICMP and DNS status messages, if a networking problem is
detected, the workload status of the agent which has found the issues
will be set to blocked. 


# Reactive States

This layer will set the following states:

* **`magpie-icmp.failed`** ICMP has failed to one or more units in the peer
relation.
* **`magpie-dns.failed`** DNS has failed to one or more units in the peer 
relation.


# Usage

```
juju deploy magpie -n 2
juju deploy magpie -n 1 --to lxc:1
```

This charm also supports the following config values:

```yaml
  check_local_hostname:
    default: true
    description: Check if local hostname is resolvable
    type: boolean
  dns_server:
    default: ''
    description: DNS Server to use (default: system default)
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
