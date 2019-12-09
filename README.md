# Overview

Magpie is a charm used for testing the networking of a juju provider/substrate.
Simply deploy Magpie charm to at least two units and watch the status messages and
debug logs.

Magpie will test:

- DNS functionality
- Local hostname lookup
- ICMP between peers
- MTU between leader and clients
- Transfer between leader and clients

Note : **MTU and transfer speed are tested with iperf2**

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

- **`magpie-icmp.failed`** ICMP has failed to one or more units in the peer relation.
- **`magpie-dns.failed`** DNS has failed to one or more units in the peer relation.

Note: work stopped on these states as it is currently unlikely magpie will be consumed
as a layer.
Please open an issue against this github repo if more states are required.

# Usage

``` code
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
    description: |
        Desired MTU for all nodes - block if the unit MTU is different
        (accounting for encapsulation). 0 disables.
    type: int
  min_speed:
    default: 0
    description: |
        Minimum transfer speed in mbits/s required to pass the test.
        0 disables.
```

e.g.

``` code
juju set magpie dns_server=8.8.8.8 required_mtu=9000 min_speed=1000
```

## Network spaces

If you use network spaces in your Juju deployment (as you should) use
`--bind '<space-name> magpie=<space-name>'` to force magpie to test that
particular network space.

It is possible to deploy several magpie charms
(as different Juju applications) to the same server each in a different
network space.

Example:

``` code
juju deploy -m magpie cs:~admcleod/magpie magpie-space1 --bind "space1 magpie=space1" -n 5 --to 0,2,1,4,3
juju deploy -m magpie cs:~admcleod/magpie magpie-space2 --bind "space2 magpie=space2" -n 3 --to 3,2,0
juju deploy -m magpie cs:~admcleod/magpie magpie-space3 --bind "space3 magpie=space3" -n 4 --to 3,2,1,0
juju deploy -m magpie cs:~admcleod/magpie magpie-space4 --bind "space4 magpie=space4" -n 4 --to 3,2,1,0
```
