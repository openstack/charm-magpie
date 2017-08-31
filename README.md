# Overview

Magpie is a charm used for testing the networking of a juju provider/substrate.
Simply deploy more than one Magpie charm and watch the status messages and
debug logs. 

Magpie will test:

 - DNS functionality
 - Local hostname lookup
 - ICMP between peers
 - MTU between leader and clients
 - Transfer between leader and clients

*MTU and transfer speed are tested with iperf2*

Status messages will show the unit numbers that have issues - if there are 
no problems, there will not be a verbose status message.

All actions, strings, queries and actions are logged in the juju logs.


# MTU Notes

The MTU size reported by iperf is sometimes 8 or 12 bytes less than the configured
MTU on the interface. This is due to TCP options not being included in the measurement,
and therefore we ignore that difference and report everything OK.

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

Note: work stopped on these states as it is currently unlikely magpie will be consumed
as a layer.
Please open an issue against this github repo if more states are required.

# Usage

```
juju deploy magpie -n 2
juju deploy magpie -n 1 --to lxd:1
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
  required_mtu:
    default: 0
<<<<<<< HEAD
    description: |
        Desired MTU for all nodes - block if the unit MTU is different 
        (accounting for encapsulation). 0 disables.
    type: int
  min_speed:
    default: 0
    description: |
        Minimum transfer speed in mbits/s required to pass the test. 
        0 disables.
=======
    decription: Desired MTU for all nodes - block if the unit MTU is different (accounting for encapsulation). 0 disables.
    type: int
  min_speed:
    default: 0
    description: Minimum transfer speed in mbits/s required to pass the test. 0 disables.
>>>>>>> 81c98c029bf014e65b4df5f88f37847903323dee
    type: int
```

e.g.

juju set magpie dns_server=8.8.8.8 required_mtu=9000 min_speed=1000

