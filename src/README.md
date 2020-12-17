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

```
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

```
juju deploy -m magpie cs:~openstack-charmers/magpie magpie-space1 --bind "space1 magpie=space1" -n 5 --to 0,2,1,4,3
juju deploy -m magpie cs:~openstack-charmers/magpie magpie-space2 --bind "space2 magpie=space2" -n 3 --to 3,2,0
juju deploy -m magpie cs:~openstack-charmers/magpie magpie-space3 --bind "space3 magpie=space3" -n 4 --to 3,2,1,0
juju deploy -m magpie cs:~openstack-charmers/magpie magpie-space4 --bind "space4 magpie=space4" -n 4 --to 3,2,1,0
```


## Bonded links testing and troubleshooting

Network bonding enables the combination of two or more network interfaces into a single-bonded
(logical) interface, which increases the bandwidth and provides redundancy. While Magpie does some
sanity checks and could reveal some configuration problems, this part of README contains some
advanced troubleshooting information, which might be useful, while identifying and fixing the issue.

There are six bonding modes:

### `balance-rr`

Round-robin policy: Transmit packets in sequential order from the first available slave through the
last. This mode provides load balancing and fault tolerance.

### `active-backup`

Active-backup policy: Only one slave in the bond is active. A different slave becomes active if, and
only if, the active slave fails. The bond's MAC address is externally visible on only one port
(network adapter) to avoid confusing the switch. This mode provides fault tolerance. The primary
option affects the behavior of this mode.

### `balance-xor`

XOR policy: Transmit based on selectable hashing algorithm. The default policy is a simple
source+destination MAC address algorithm. Alternate transmit policies may be selected via the
`xmit_hash_policy` option, described below. This mode provides load balancing and fault tolerance.

### `broadcast`

Broadcast policy: transmits everything on all slave interfaces. This mode provides fault tolerance.

### `802.3ad` (LACP)

Link Aggregation Control Protocol (IEEE 802.3ad LACP) is a control protocol that automatically
detects multiple links between two LACP enabled devices and configures them to use their maximum
possible bandwidth by automatically trunking the links together. This mode has a prerequisite -
the switch(es) ports should have LACP configured and enabled.

### `balance-tlb`

Adaptive transmit load balancing: channel bonding that does not require any special switch support.
The outgoing traffic is distributed according to the current load (computed relative to the speed)
on each slave. Incoming traffic is received by the current slave. If the receiving slave fails,
another slave takes over the MAC address of the failed receiving slave.

### `balance-alb`

Adaptive load balancing: includes balance-tlb plus receive load balancing (rlb) for IPV4 traffic,
and does not require any special switch support. The receive load balancing is achieved by ARP
negotiation.

The most commonly used modes are `active-backup` and `802.3ad` (LACP), and while active-backup
does not require any thirdparty configuration, it has its own cons - for example, it can't multiply
the total bandwidth of the link, while 802.3ad-based bond could utilize all bond members, therefore
multiplying the bandwidth. However, in order to get a fully working LACP link, an appropriate
configuration has to be done both on the actor (link initiator) and partner (switch) side. Any
misconfiguration could lead to the link loss or instability, therefore it's very imporant to have
correct settings applied to the both sides of the link.

A quick overview of the LACP link status could be obtained by reading the
`/proc/net/bonding/<bond_name>` file.

```
$ sudo cat /proc/net/bonding/bondM
Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer3+4 (1)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0

802.3ad info
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 82:23:80:a1:a9:d3
Active Aggregator Info:
 Aggregator ID: 1
 Number of ports: 2
 Actor Key: 15
 Partner Key: 201
 Partner Mac Address: 02:01:00:00:01:01

Slave Interface: eno3
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 3c:ec:ef:19:eb:30
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 82:23:80:a1:a9:d3
    port key: 15
    port priority: 255
    port number: 1
    port state: 63
details partner lacp pdu:
    system priority: 65534
    system mac address: 02:01:00:00:01:01
    oper key: 201
    port priority: 1
    port number: 12
    port state: 63

Slave Interface: eno1
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 3c:ec:ef:19:eb:2e
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 82:23:80:a1:a9:d3
    port key: 15
    port priority: 255
    port number: 2
    port state: 63
details partner lacp pdu:
    system priority: 65534
    system mac address: 02:01:00:00:01:01
    oper key: 201
    port priority: 1
    port number: 1012
    port state: 63
```

The key things an operator should take a look at is:

- LACP rate
- Actor Churn State
- Partner Churn State
- Port State

### LACP rate

The Link Aggregation Control Protocol (LACP) provides a standardized means for exchanging
information between Partner Systems on a link to allow their Link Aggregation Control instances to
reach agreement on the identity of the LAG to which the link belongs, move the link to that LAG, and
enable its transmission and reception functions in an orderly manner. The protocol depends upon the
transmission of information and state, rather than the transmission of commands. LACPDUs (LACP Data
Unit) sent by the first party (the Actor) convey to the second party (the Actor’s protocol Partner)
what the Actor knows, both about its own state and that of the Partner.

Periodic transmission of LACPDUs occurs if the LACP Activity control of either the Actor or the
Partner is Active LACP. These periodic transmissions will occur at either a slow or fast
transmission rate depending upon the expressed LACP_Timeout preference (Long Timeout or Short
Timeout) of the Partner System.

### Actor/Partner Churn State

In general, "Churned" port status means that the parties are unable to reach agreement upon the
desired state of a link. Under normal operation of the protocol, such a resolution would be reached
very rapidly; continued failure to reach agreement can be symptomatic of component failure, of the
presence of non-standard devices on the link concerned, or of mis-configuration. Hence, detection of
such failures is signalled by the Churn Detection algorithm to the operator in order to prompt
administrative action to further resolution.

### Port State

Both of the Actor and Partner state are variables, encoded as individual bits within a single octet,
as follows.

0) LACP_Activity: Device intends to transmit periodically in order to find potential
members for the aggregate. Active LACP is encoded as a 1; Passive LACP as a 0.
1) LACP_Timeout: This flag indicates the Timeout control value with regard to this link. Short
Timeout is encoded as a 1; Long Timeout as a 0.
2) Aggregability: This flag indicates that the system considers this link to be Aggregateable; i.e.,
a potential candidate for aggregation. If FALSE (encoded as a 0), the link is considered to be
Individual; i.e., this link can be operated only as an individual link. Aggregatable is encoded as a
1; Individual is encoded as a 0.
3) Synchronization: Indicates that the bond on the transmitting machine is in sync with what’s being
advertised in the LACP frames, meaning the link has been allocated to the correct LAG, the group has
been associated with a compatible Aggregator, and the identity of the LAG is consistent with the
System ID and operational Key information transmitted. "In Sync" is encoded as a 1; "Out of sync" is
encoded as a 0.
4) Collecting: Bond is accepting traffic received on this port, collection of incoming frames on
this link is definitely enabled and is not expected to be disabled in the absence of administrative
changes or changes in received protocol information. True is encoded as a 1; False is encoded as a
0.
5) Distributing: Bond is sending traffic using this ports encoded. Same as above, but for egress
traffic. True is encoded as a 1; False is encoded as a 0.
6) Defaulted: Determines, whether the receiving bond is using default (administratively defined)
parameters, if the information was received in an LACP PDU. Default settings are encoded as a 1,
LACP PDU is encoded as 0.
7) Expired: Is the bond in the expired state. Yes encoded as a 1, No encoded as a 0.

In the example output above, both of the port states are equal to 63. Let's decode:

```
$ python3
Python 3.8.4 (default, Jul 17 2020, 15:44:37)
[Clang 11.0.3 (clang-1103.0.32.62)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> bin(63)
'0b111111'
```

Reading right to the left:

LACP Activity: Active
LACP Timeout: Short
Aggregability: Link is Aggregatable
Synchronization: Link in sync
Collecting: True - bond is accepting the traffic
Distributing: True - bond is sending the traffic
Defaulted: Info received from LACP PDU
Expired: False - link is not expired

The above status represents the **fully healthy bond** without any LACP-related issues. Also, for
the operators' convenience, the [lacp_decoder.py](src/tools/lacp_decoder.py) script could be used to
quickly convert the status to some human-friendly format.

However, the situations where one of the links is misconfigured are happening too, so let's assume
we have the following:

```
$ sudo cat /proc/net/bonding/bondm
Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer3+4 (1)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0

802.3ad info
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: b4:96:91:6d:20:fc
Active Aggregator Info:
        Aggregator ID: 2
        Number of ports: 1
        Actor Key: 9
        Partner Key: 32784
        Partner Mac Address: 00:23:04:ee:be:66

Slave Interface: enp197s0f2
MII Status: up
Speed: 100 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: b4:96:91:6d:20:fe
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: churned
Partner Churn State: none
Actor Churned Count: 1
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: b4:96:91:6d:20:fc
    port key: 7
    port priority: 255
    port number: 1
    port state: 7
details partner lacp pdu:
    system priority: 32667
    system mac address: 00:23:04:ee:be:66
    oper key: 32784
    port priority: 32768
    port number: 16661
    port state: 13

Slave Interface: enp197s0f0
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: b4:96:91:6d:20:fc
Slave queue ID: 0
Aggregator ID: 2
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: b4:96:91:6d:20:fc
    port key: 9
    port priority: 255
    port number: 2
    port state: 63
details partner lacp pdu:
    system priority: 32667
    system mac address: 00:23:04:ee:be:66
    oper key: 32784
    port priority: 32768
    port number: 277
    port state: 63
```

As we could see, one of the links has different port states for both partner and actor, while second
one has 63 for both - meaning, the first one is problematic and we'd need to dive more into this
problem.

Let's decode both of the statuses, using the mentioned script:

```
$ python ./lacp-decoder.py 7 13
(Equal for both ports) LACP Activity: Active LACP
LACP Timeout: Short (Port 1) / Long (Port 2)
(Equal for both ports) Aggregability: Aggregatable
Synchronization: Link out of sync (Port 1) / Link in sync (Port 2)
(Equal for both ports) Collecting: Ingress traffic: Rejecting
(Equal for both ports) Distributing: Egress trafic: Not sending
(Equal for both ports) Is Defaulted: Settings are received from LACP PDU
(Equal for both ports) Link Expiration: No
```

The above output means, that there is two differences between these statuses: LACP Timeout and
Synchronization. That means two things:

1) the Partner side (a switch side in most of the cases) has incorrectly configured LACP timeout
control. To resolve this, an operator has to either change the LACP rate from the Actor (e.g a
server) side to "Slow", or adjust the Partner (e.g switch) LACP rate to "Fast".
2) the Partner side considers this physical link as a part of different link aggregation group. The
switch config has to be revisited and link aggregation group members needs to be verified again,
ensuring there is no extra or wrong links configured as part of the single LAG.

After addressing the above issues, the port state will change to 63, which means "LACP link is fully
functional".

# Bugs

Please report bugs on [Launchpad](https://bugs.launchpad.net/charm-magpie/+filebug).

For general questions please refer to the OpenStack [Charm Guide](https://docs.openstack.org/charm-guide/latest/).
