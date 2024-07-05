# Copyright 2020 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Utility functions for the magpie charm.

These utilities shouldn't contain anything charm-specific.
"""

import asyncio
import datetime
import json
import logging
import math
import os
import re
import subprocess
from enum import Enum, unique
from functools import lru_cache
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import netaddr
import netifaces
import yaml
from prometheus_client import Gauge, start_http_server

logger = logging.getLogger(__name__)


@unique
class DigLookupType(Enum):
    """Represent a lookup type for parsing dig commands."""

    CNAME = "CNAME"
    FORWARD = "Forward"
    REVERSE = "Reverse"


class HostWithIp(NamedTuple):
    """Represent a unit with its ip address."""

    name: str
    ip: str


class CollectDataConfig(NamedTuple):
    """Config args for collecting local info."""

    required_mtu: int
    bonds_to_check: str
    lacp_passive_mode: bool
    local_ip: str


class PingConfig(NamedTuple):
    """Config args for ping result."""

    timeout: int
    tries: int
    interval: float
    required_mtu: int


class PingResult(NamedTuple):
    """Resulting stats from running a ping."""

    received: int
    transmitted: int


class DnsConfig(NamedTuple):
    """Config for running a dns check action."""

    server: str
    tries: int
    timeout: int


# from charmhelpers.core.host
def get_nic_mtu(nic):
    """Return the Maximum Transmission Unit (MTU) for a network interface."""
    cmd = ["ip", "addr", "show", nic]
    ip_output = subprocess.check_output(cmd).decode("UTF-8", errors="replace").split("\n")
    mtu = ""
    for line in ip_output:
        words = line.split()
        if "mtu" in words:
            mtu = words[words.index("mtu") + 1]
    return mtu


# from charmhelpers.contrib.network.ip
def get_iface_from_addr(addr):
    """Work out on which interface the provided address is configured."""
    ll_key = re.compile("(.+)%.*")
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        for inet_type in addresses:
            for _addr in addresses[inet_type]:
                _addr = _addr["addr"]
                # link local
                raw = ll_key.match(_addr)
                if raw:
                    _addr = raw.group(1)

                if _addr == addr:
                    logger.debug("Address '%s' is configured on iface '%s'" % (addr, iface))
                    return iface

    msg = "Unable to infer net iface on which '%s' is configured" % (addr)
    raise Exception(msg)


# from charmhelpers.contrib.network.ip
def get_address_in_network(network_str: str) -> Optional[str]:
    """Get an IPv4 or IPv6 address within the network from the host.

    :param network_str (str): CIDR presentation format. For example,
        '192.168.1.0/24'.
    """
    network = netaddr.IPNetwork(network_str)
    for iface in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(iface)
        except ValueError:
            # If an instance was deleted between
            # netifaces.interfaces() run and now, its interfaces are gone
            continue
        if network.version == 4 and netifaces.AF_INET in addresses:
            for addr in addresses[netifaces.AF_INET]:
                cidr = netaddr.IPNetwork("%s/%s" % (addr["addr"], addr["netmask"]))
                if cidr in network:
                    return str(cidr.ip)

        if network.version == 6 and netifaces.AF_INET6 in addresses:
            for addr in addresses[netifaces.AF_INET6]:
                cidr = _get_ipv6_network_from_address(addr)
                if cidr and cidr in network:
                    return str(cidr.ip)

    return None


def _get_ipv6_network_from_address(address):
    """Get an netaddr.IPNetwork for the given IPv6 address.

    :param address: a dict as returned by netifaces.ifaddresses
    :returns netaddr.IPNetwork: None if the address is a link local or loopback
    address.
    """
    if address["addr"].startswith("fe80") or address["addr"] == "::1":
        return None

    prefix = address["netmask"].split("/")
    if len(prefix) > 1:
        netmask = prefix[1]
    else:
        netmask = address["netmask"]
    return netaddr.IPNetwork("%s/%s" % (address["addr"], netmask))


def disable_i40e_lldp_agent():
    """Disable the internal NIC LLDP agent if available."""
    path = "/sys/kernel/debug/i40e"
    if os.path.isdir(path):
        logger.info("Disabling NIC internal LLDP agent")
        for r, dirs, files in os.walk(path):
            for dir in dirs:
                with open(f"{path}/{dir}/command", "w") as fh:
                    fh.write("lldp stop")


def configure_lldpd():
    """Configure and start lldpd."""
    disable_i40e_lldp_agent()
    os.system("apt install -y lldpd")


@lru_cache
def collect_lldp_data():
    """Run lldpcli and return json data."""
    return json.loads(
        subprocess.check_output(
            ["lldpcli", "show", "neighbors", "details", "-f", "json"],
            text=True,
        )
    )


def get_lldp_interface(iface: str) -> Optional[dict]:
    """Get data for an interface from lldp."""
    for i in collect_lldp_data().get("lldp", {}).get("interface", []):
        if iface in i:
            return i[iface]
    return None


def get_interface_vlan(iface: str) -> Optional[str]:
    """Get the vlan from an interface from lldp."""
    data = get_lldp_interface(iface)
    if data:
        vlan = data.get("vlan", {}).get("vlan-id", None)
        if not vlan:
            logger.info("No LLDP data for %s", iface)
        return vlan


def get_interface_port_descr(iface: str) -> Optional[str]:
    """Get port description from an interface from lldp."""
    data = get_lldp_interface(iface)
    if data:
        vlan = data.get("port", {}).get("descr", None)
        if not vlan:
            logger.info("No LLDP data for %s", iface)
        return vlan


async def run(cmd) -> str:
    """Run a command and return the stdout, async."""
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await proc.communicate()

    if stdout:
        return stdout.decode()
    if stderr:
        print("[stderr]")
        print(stderr.decode())
    return ""


def run_iperf(
    node_name: str, ip: str, iperf_batch_time: int, concurrency: int, min_speed: str
) -> Dict[str, Any]:
    """Run an iperf client command.

    The following is an example of the output
    $ iperf -c 192.168.2.1 -t 10 --port 5001 -P 2 --reportstyle c
    19700101000000,192.168.2.2,60266,192.168.2.1,5001,2,0.0-10.1,95158332,75301087
    19700101000000,192.168.2.2,60268,192.168.2.1,5001,1,0.0-10.1,161742908,127989222.

    First field: timestamp of the iperf run
        As of right now with iperf 2.1.7 (Jammy), the timestamp
        is always outputting 19700101000000
    Second field: source IP address
    Third field: source port
    Fourth field: destination address
    Fifth field: destination port
    Sixth field: Session number when in parallel, iperf doesn't
        seem to reorder the output by the session number
    Seventh field: duration of test
    Eighth field: transferred bytes
    Ninth field: average speed in bits per second
    """
    cmd = [
        "iperf",
        "-t",
        str(iperf_batch_time),
        "-c",
        ip,
        "--port",
        "5001",
        "-P",
        str(concurrency),
        "--reportstyle",
        "c",
    ]
    logger.info(cmd)
    out = ""
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        logger.warn(e.stderr)

    results = {
        "src_port": [],
        "dest_port": "",
        "dest_node": node_name,
        "session": [],
        "transferred_bytes": 0,
        "bits_per_second": 0,
    }

    src_ip = get_src_ip_from_dest(ip)
    interface = get_iface_from_addr(src_ip)
    src_mac = get_iface_mac(interface)
    results["src_interface"] = interface
    results["src_mac"] = src_mac
    results["src_ip"] = src_ip
    results["dest_ip"] = ip

    for line in out.splitlines():
        (
            timestamp,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            session,
            time_interval,
            xferred_bytes,
            bits_per_s,
        ) = line.split(",")

        # On Focal, a supplementary line with the summarised total
        # needs to be ignored, this can be recognised with the
        # session being set to -1 on the line
        if session != "-1":
            # The following values will be identical on each line,
            # so only set the fields once.
            if not results.get("timestamp"):
                results["timestamp"] = timestamp
                results["dest_port"] = dest_port
                results["time_interval"] = time_interval
                results["concurrency"] = concurrency

            # for now magpie only use one iperf server as
            # destination, it is not useful to record multiple
            # time the destination port since it is identical
            results["src_port"].append(int(src_port))
            results["session"].append(int(session))
            results["transferred_bytes"] += int(xferred_bytes)
            results["bits_per_second"] += int(bits_per_s)

    results["GBytes_transferred"] = round(
        float(results["transferred_bytes"] / 1024**3),
        3,
    )
    results["Mbits_per_second"] = int(results["bits_per_second"] / 1024**2)

    # retrieve supplementary information not provided by iperf
    dest_mac = get_dest_mac(interface, results["dest_ip"])
    results["dest_mac"] = dest_mac

    logger.info(
        f"Source: {results['src_ip']}, "
        f"Destination: {results['dest_ip']} "
        f"({results['dest_node']}) : "
        f"{results['GBytes_transferred']} GB, "
        f"{results['Mbits_per_second']} Mbps"
    )

    link_speed = get_link_speed(interface)
    results["min_speed_check"] = status_for_speed_check(
        min_speed, results["bits_per_second"], link_speed
    )

    return results


class Iperf:
    """Class to manage iperf server/client."""

    def __init__(self, model_name: str, app_name: str, unit_name: str, with_prometheus: bool):
        self.iperf_out = f"/home/ubuntu/iperf_output.{app_name}.txt"
        self.with_prometheus = with_prometheus
        self.model_name = model_name
        self.unit_name = unit_name
        self.metrics = {}

        self.bandwidth_metric = Gauge(
            "magpie_iperf_bandwidth",
            "magpie iperf bandwidth (bits/s)",
            ["model", "src", "dest"],
        )
        self.concurrency_metric = Gauge(
            "magpie_iperf_concurrency",
            "magpie iperf process concurrency",
            ["model", "src", "dest"],
        )

    def listen(self, cidr: str, fallback_bind_address: str):
        """Start the iperf server, in the background.

        Bound to address in `cidr` if not an empty string,
        otherwise to the fallback bind address.

        Return immediately
        """
        if cidr:
            bind_address = get_address_in_network(cidr)
        else:
            bind_address = fallback_bind_address
        cmd = f"iperf -s -fm --port 5001 -B {bind_address} | tee {self.iperf_out} &"
        os.system(cmd)

    def _hostcheck(
        self,
        node: HostWithIp,
        total_runtime: int,
        batch_time: int,
        progression: List[int],
        min_speed: str,  # formatted as int or percentage (N%)
    ):
        """Run iperf against the specified node."""
        output = []
        increment_interval = datetime.timedelta(
            seconds=math.ceil(total_runtime / len(progression))
        )
        start_time = datetime.datetime.now()
        finish_time = start_time + datetime.timedelta(seconds=total_runtime)

        while datetime.datetime.now() < finish_time:
            concurrency = progression[
                min(
                    len(progression),
                    math.ceil((datetime.datetime.now() - start_time) / increment_interval),
                )
                - 1
            ]

            result = run_iperf(
                node.name,
                node.ip,
                batch_time,
                concurrency,
                min_speed,
            )
            output.append(result)

            if self.with_prometheus:
                self.bandwidth_metric.labels(
                    model=self.model_name,
                    src=self.unit_name,
                    dest=node.name,
                ).set(result["bits_per_second"])
                self.concurrency_metric.labels(
                    model=self.model_name,
                    src=self.unit_name,
                    dest=node.name,
                ).set(concurrency)

        return output

    def batch_hostcheck(
        self,
        nodes: List[HostWithIp],
        total_runtime: int,
        batch_time: int,
        progression: List[int],
        min_speed: str,  # formatted as int or percentage (N%)
    ):
        """Run iperf against all nodes."""
        if self.with_prometheus:
            start_http_server(80)

        output = []
        for node in nodes:
            output.extend(self._hostcheck(node, total_runtime, batch_time, progression, min_speed))
        return output


async def ping(
    addr: str,
    timeout: int,
    count: int,
    interval: float,
    mtu: int,
) -> PingResult:
    """Ping `addr` with provided options."""
    args = [
        "ping",
        "-c",
        str(count),
        "-i",
        str(interval),
        "-W",
        str(timeout),
    ]
    if mtu:
        args.extend(("-M", "do", "-s", str(int(mtu) - 28)))
    args.append(addr)
    args = " ".join(args)

    # Yes this is a blocking call, but doesn't block for long.
    # We only need to parallelise the ping calls, which block for much longer.
    logger.debug("Ping command: {}".format(args))

    stdout = await run(args)

    logger.info(f"ping stdout {stdout}")
    match = re.search(r"(\d+)\s*packets\s+transmitted,\s*(\d+)\s*received", stdout)
    if match:
        return PingResult(received=int(match.group(2)), transmitted=int(match.group(1)))
    logger.debug(f"pinging {addr} failed with output: '{stdout}'")
    return PingResult(received=0, transmitted=count)


def check_local_hostname():
    """Check hostname is defined and we can look it up in the local NSS."""
    local_hostname = subprocess.check_output("hostname", text=True).strip()
    lookup_cmd = "getent hosts {}".format(local_hostname)
    logger.info("Looking up local hostname: {}".format(local_hostname))
    try:
        result = subprocess.check_output(lookup_cmd, shell=True).decode("utf-8").rstrip()
        result = ""
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = local_hostname
        stderr = exc.returncode
    return result, stderr


def status_for_speed_check(min_speed: str, speed: int, link_speed: int) -> Dict[str, Any]:
    """Generate a message and ok status for the iperf speed test.

    :param min_speed: string value of min-speed from action params
    :type min_speed: str
    :param speed: speed in mbit/s from iperf
    :type speed: float
    :param link_speed: link speed in mbit/s
    :type link_speed: int
    """
    if not re.match(r"^\d+%?$", min_speed):
        return {
            "ok": False,
            "message": f"invalid min_speed: {min_speed}",
        }

    if int(min_speed.rstrip("%")) == 0:
        return {
            "ok": True,
            "message": "min-speed disabled",
        }

    if "%" in min_speed:
        # virtual link with no defined speed
        if link_speed < 0:
            logger.info(
                "link speed negative, so unable to calculate value for min_speed percentage"
            )
            return {
                "ok": False,
                "message": "unknown, link speed undefined",
            }

        # convert percentage to integer mbit/s
        resolved_min_speed = int(min_speed.rstrip("%")) * link_speed // 100
    else:
        resolved_min_speed = int(min_speed)

    if resolved_min_speed <= speed:
        return {
            "ok": True,
            "message": f"{speed} >= {resolved_min_speed} mbit/s",
        }
    else:
        return {
            "ok": False,
            "message": f"failed: {speed} < {resolved_min_speed} mbit/s",
        }


def check_port_description():
    """Check ports have a sensible description.

    It's good practice for the port descriptions to contain the hostname.
    But it is not mandatory, and should not be considered a blocking issue.
    """
    iface_dir = "/sys/class/net"
    status = None
    local_hostname = subprocess.check_output("hostname", shell=True).decode("utf-8").rstrip()
    for r, dirs, files in os.walk(iface_dir):
        for dir in dirs:
            if dir == "lo" or dir.startswith("vnet") or dir.startswith("veth"):
                continue
            if check_iface_type(dir) == "eth":
                if not check_iface_down(dir):
                    desc = get_interface_port_descr(dir)
                    logger.info("Port {} description {}".format(dir, desc))
                    if desc:
                        if local_hostname not in desc:
                            if status:
                                status = "{} {}:{}".format(status, dir, desc)
                            else:
                                status = "{}:{}".format(dir, desc)
    if status:
        return "failed: {}".format(status)
    else:
        return "ok"


def check_iface_type(iface: str) -> str:
    """Return the type of an interface, given the interface name."""
    iface_dir = "/sys/class/net/{}".format(iface)
    with open("{}/uevent".format(iface_dir)) as fos:
        content = fos.read()
        if "DEVTYPE" in content:
            return "complex"
    return "eth"


def check_iface_down(iface: str) -> Optional[str]:
    """Check if the interface is down.

    Return "down" if it is down.
    """
    iface_dir = "/sys/class/net/{}".format(iface)
    with open("{}/operstate".format(iface_dir)) as fos:
        content = fos.read()
        if "up" not in content:
            return "down"
    with open("{}/carrier".format(iface_dir)) as fos:
        content = fos.read()
        if "1" not in content:
            return "down"
    return None


def check_aggregator_id(bond_iface, slave_iface) -> Optional[str]:
    """Check aggregator id, return a string message about mismatch if there was a mismatch."""
    bond_iface_dir = "/sys/class/net/{}/bonding".format(bond_iface)
    slave_iface_dir = "/sys/class/net/{}/bonding_slave".format(slave_iface)
    with open("{}/ad_aggregator".format(bond_iface_dir)) as fos:
        bond_aggr_value = fos.read()
    with open("{}/ad_aggregator_id".format(slave_iface_dir)) as fos:
        slave_aggr_value = fos.read()
    if bond_aggr_value != slave_aggr_value:
        return "aggregate_id_mismatch"
    return None


def check_lacp_port_state(iface: str, lacp_passive_mode: bool) -> Optional[str]:
    """Check for mismatch in the lacp ports."""
    iface_dir = "/sys/class/net/{}/bonding_slave".format(iface)
    with open("{}/ad_actor_oper_port_state".format(iface_dir)) as fos:
        actor_port_state = fos.read()
    with open("{}/ad_partner_oper_port_state".format(iface_dir)) as fos:
        partner_port_state = fos.read()

    if (
        actor_port_state != partner_port_state
        # check if this is an acceptable mismatch in the LACP activity mode
        and not (
            lacp_passive_mode
            # and the only difference is the LACP activity bit
            # (1111_1110 bitmask to ignore LACP activity bit in comparison)
            and (int(actor_port_state) & 254) == (int(partner_port_state) & 254)
        )
    ):
        return "lacp_port_state_mismatch"
    return None


def get_bond_mode(bond: str) -> str:
    """Return a string describing the mode of the bond."""
    bond_path = "/sys/class/net/{}".format(bond)
    with open("{}/bonding/mode".format(bond_path)) as fos:
        content = fos.read()
        if "balance-rr" in content:
            return "balance_rr"
        elif "active-backup" in content:
            return "active_backup"
        elif "balance-xor" in content:
            return "balance_xor"
        elif "broadcast" in content:
            return "broadcast"
        elif "802.3ad" in content:
            return "lacp"
        elif "balance-tlb" in content:
            return "balance_tlb"
        elif "balance-alb" in content:
            return "balance_alb"
    return "others"


def check_bond(bond: str, lacp_passive_mode: bool) -> Optional[str]:
    """Check the bond, returning a string message if there are issues."""
    bond_path = "/sys/class/net/{}".format(bond)
    if not os.path.isdir(bond_path):
        return "missing"
    if check_iface_down(bond):
        return "down"

    with open("{}/bonding/slaves".format(bond_path)) as fos:
        slaves = fos.read().split()
        vlan = None
        for slave in slaves:
            if check_iface_down(slave):
                return "{} down".format(slave)
            if vlan and vlan != get_interface_vlan(slave):
                return "vlan mismatch"
            else:
                vlan = get_interface_vlan(slave)

        if get_bond_mode(bond) == "lacp":
            for slave in slaves:
                if check_aggregator_id(bond, slave):
                    return "Aggregator ID mismatch"
                if check_lacp_port_state(slave, lacp_passive_mode):
                    return "LACP port state mismatch"
    return None


def check_bonds(bonds: str, lacp_passive_mode: bool) -> Dict[str, Any]:
    """Check all the bonds, return an informative message."""
    results = {}
    for bond in (b.strip() for b in bonds.split(",")):
        error = check_bond(bond, lacp_passive_mode)
        results[bond] = {
            "ok": not error,
            "error": error,
        }
    return results


def get_link_speed(iface: str) -> int:
    """Return the link speed of an interface."""
    try:
        with open("/sys/class/net/{}/speed".format(iface)) as f:
            return int(f.read())
    except OSError as e:
        logger.warn("Unable to determine link speed for {}: {}".format(iface, str(e)))
        return -1


def get_src_ip_from_dest(address: str) -> str:
    """Return the source ip given a destination ip.

    Return an empty string on failure
    """
    args = [
        "ip",
        "-j",
        "route",
        "get",
        address,
    ]

    output = json.loads(
        subprocess.check_output(
            args,
            text=True,
        )
    )

    # if there is no results, iproute returns an empty list
    if output:
        return output[0]["prefsrc"]
    else:
        return ""


def get_iface_mac(iface: str) -> str:
    """Return the mac address for an interface."""
    if iface in netifaces.interfaces():
        addr = netifaces.ifaddresses(iface)
        mac = addr[netifaces.AF_LINK][0]["addr"]
        return mac
    else:
        logger.warn("Unable to retrieve MAC from interface {}".format(iface))
        return ""


def get_dest_mac(iface: str, address: str) -> str:
    """Return the mac address of a destination address if possible (otherwise empty string)."""
    args = [
        "ip",
        "-j",
        "neigh",
        "show",
        "dev",
        iface,
        "to",
        address,
    ]
    output = json.loads(
        subprocess.check_output(
            args,
            text=True,
        )
    )

    # if there is no matched address, iproute returns an empty list
    if output:
        mac_addr = output[0]["lladdr"]
        return mac_addr
    else:
        return ""


async def async_check_ping(node: HostWithIp, config: PingConfig) -> Tuple[str, str]:
    """Ping a unit, returning (node name, string message about packets received)."""
    logger.info("Pinging unit: " + node.name)
    (received, transmitted) = await ping(
        node.ip, config.timeout, config.tries, config.interval, config.required_mtu
    )
    if transmitted > 0 and received == transmitted:
        logger.info(
            f"Ping OK for unit: {node.name}.  "
            f"{transmitted} packets transmitted, {received} received"
        )
        return (node.name, "ok")
    else:
        logger.warn(
            f"Ping FAILED for unit: {node.name}.  "
            f"{transmitted} packets transmitted, {received} received"
        )
        return (node.name, f"{received}/{transmitted} packets received")


def check_ping(targets: List[HostWithIp], config: PingConfig) -> Dict[str, str]:
    """Ping nodes and return unreachable unit names -> message.

    This is mostly a sync wrapper around async_check_ping.
    """
    return dict(
        asyncio.get_event_loop().run_until_complete(
            asyncio.gather(*[async_check_ping(target, config) for target in targets])
        )
    )


def check_dns(nodes: List[HostWithIp], config: DnsConfig) -> Dict[str, Any]:
    """Check dns for given nodes."""
    results = {}

    for node in nodes:
        results[node.name] = {}

        logger.info("Reverse lookup for ip: {}, node: {}".format(node.ip, node.name))
        hostnames, ret_code = reverse_dns(node.ip, config.server, config.tries, config.timeout)
        logger.info(f"Reverse result for {node.name}, hostname: {hostnames}, exitcode: {ret_code}")

        if ret_code:
            results[node.name]["reverse"] = {"hostnames": [], "ok": False}
            logger.error(f"Reverse FAILED for: {node.name}")
            continue

        else:
            logger.info(f"Reverse OK for {node.name}")
            results[node.name]["reverse"] = {"hostnames": hostnames, "ok": True}

            logger.info(f"Forward lookup for hostnames: {hostnames}, node: {node.name}")

            results[node.name]["forward"] = {}
            for hostname in hostnames:
                forward_ips, ret_code = forward_dns(
                    hostname, config.server, config.tries, config.timeout
                )

                logger.info(
                    f"Forward result for {node.name}, ips: {forward_ips}, exitcode: {ret_code}"
                )

                if ret_code:
                    logger.error(f"Forward FAILED for: {node.name}")
                    results[node.name]["forward"][hostname] = {"ok": False}

                else:
                    logger.info(f"Forward OK for: {node.name}")

                    results[node.name]["forward"][hostname] = {"ips": forward_ips, "ok": True}

                    if node.ip not in forward_ips:
                        logger.error(
                            "Original IP and Forward MATCH FAILED for"
                            f" unit: {node.name}, Original: {node.ip}, Forward: {forward_ips}"
                        )
                        results[node.name]["forward"][hostname]["match"] = True

                    else:
                        logger.info(
                            "Original IP and Forward MATCH OK for"
                            f" unit: {node.name}, Original: {node.ip}, Forward: {forward_ips}"
                        )
                        results[node.name]["forward"][hostname]["match"] = False

    return results


def _execute_dig(
    cmd: str, server: str, tries: int, timeout: int, lookup_type: DigLookupType
) -> Tuple[str, int]:
    """Run a dig command and return parsed information from the result."""
    try:
        output = subprocess.check_output(cmd, shell=True).decode("utf-8").rstrip()
        result, ret_code = parse_dig_yaml(
            output,
            server,
            tries,
            timeout,
            is_reverse_query=lookup_type == DigLookupType.REVERSE,
        )
    except subprocess.CalledProcessError as exc:
        result = f"{lookup_type} DNS lookup error: {exc.output}"
        ret_code = exc.returncode
    if result == "":
        result = f"No {lookup_type} response"
        ret_code = 1
    return result, ret_code


def resolve_cname(label, server, tries, timeout, rec_type) -> Tuple[str, int]:
    """Resolve cname with dig, returning the results."""
    cmd = "/usr/bin/dig {} +yaml +tries={} +time={}".format(
        label,
        tries,
        timeout,
    )
    if rec_type:
        cmd += " " + rec_type
    if server:
        cmd = "{} @{}".format(cmd, server)
    return _execute_dig(cmd, server, tries, timeout, DigLookupType.CNAME)


def parse_dig_yaml(
    output: str, server: str, tries: int, timeout: int, is_reverse_query: bool
) -> Tuple[str, int]:
    """Process and parse yaml from dig output."""
    try:
        responses = yaml.safe_load(output)
    except yaml.YAMLError:
        result = f"Cannot parse {output} as YAML"
        ret_code = 2
        return result, ret_code

    result = ""
    ret_code = 0
    for response in responses:
        if response["type"] == "MESSAGE":
            response_data = response["message"]["response_message_data"]
            for answer in response_data.get("ANSWER_SECTION", []):
                logger.debug(
                    'DNS answer for "{}" received: {}'.format(
                        response.get("QUESTION_SECTION", [""])[0], answer
                    )
                )
                split_answer = answer.split(" ")
                rec_type = split_answer[3]
                rrdata = " ".join(split_answer[4:])
                if rec_type in ("PTR", "CNAME") and rrdata[-1] == ".":
                    rrdata = rrdata[:-1]
                if rec_type == "CNAME":
                    cname_result, ret_code = resolve_cname(
                        rrdata,
                        server,
                        tries,
                        timeout,
                        "PTR" if is_reverse_query else "",
                    )
                    if ret_code != 0:
                        return cname_result, ret_code
                    result += cname_result + "\n"
                else:
                    result += rrdata + "\n"

    return result.strip(), ret_code


def reverse_dns(ip: str, server: str, tries: int, timeout: int) -> Tuple[List[str], int]:
    """Return results of a reverse dns call with dig.

    ([list of hostnames], return code)
    """
    cmd = f"/usr/bin/dig -x {ip} +yaml +tries={tries} +time={timeout}"
    if server:
        cmd = f"{cmd} @{server}"
    logger.debug("DNS Reverse command: {}".format(cmd))
    reverse, ret_code = _execute_dig(cmd, server, tries, timeout, DigLookupType.REVERSE)
    return reverse.split(), ret_code


def forward_dns(ip: str, server: str, tries: int, timeout: int) -> Tuple[List[str], int]:
    """Return results of a forward dns call with dig."""
    cmd = f"/usr/bin/dig -x {ip} +yaml +tries={tries} +time={timeout}"
    if server:
        cmd = f"{cmd} @{server}"
    logger.debug("DNS Forward command: {}".format(cmd))
    output, ret_code = _execute_dig(cmd, server, tries, timeout, DigLookupType.FORWARD)
    return output.splitlines(), ret_code


def collect_local_data(config: CollectDataConfig) -> Dict[str, Any]:
    """Retrieve information about this magpie unit node.

    Return a dictionary of the data discovered.
    """
    iface_lines = subprocess.check_output(
        ["ip", "route", "show", "to", "match", config.local_ip], text=True
    )
    # example output:
    #     default via 192.168.1.1 dev enp3s0 proto dhcp metric 100
    #     192.168.1.0/24 dev enp3s0 proto kernel scope link src 192.168.1.101 metric 100
    line = ""
    for line in iface_lines.splitlines():
        if re.match(".* via .*", line) is None:
            break
    if not line:
        # TODO: handle this case better
        raise AssertionError("unexpected error with ip route output")
    primary_iface = str(line).split("dev")[1].split(" ")[1]
    iface_mtu = int(get_nic_mtu(primary_iface))
    link_speed = get_link_speed(primary_iface)

    port_description = check_port_description()

    cfg_check_bonds = config.bonds_to_check
    # Attempt to find the bond interfaces and create a comma-delimited
    # string out of them for use by the check_bonds() call below.
    all_bonds_path = "/sys/class/net/bonding_masters"
    if cfg_check_bonds.upper() == "AUTO" and os.path.exists(all_bonds_path):
        with open(all_bonds_path) as fos:
            all_bonds = fos.read()
            if all_bonds:
                cfg_check_bonds = all_bonds.replace(" ", ",")
    elif cfg_check_bonds.upper() == "AUTO":
        logger.debug("No bond interfaces available.")
        cfg_check_bonds = ""
    bonds = ""
    if cfg_check_bonds:
        bonds = check_bonds(cfg_check_bonds, config.lacp_passive_mode)

    return {
        "primary iface": primary_iface,
        "link speed": link_speed,
        "lldp": {
            "port description": port_description,
        },
        "bonds": {
            "checked": bool(cfg_check_bonds),
            "bonds": bonds,
        },
        "mtu": {
            "local mtu": iface_mtu,
            "required": config.required_mtu,
            "ok": not config.required_mtu or (0 <= (iface_mtu - config.required_mtu) <= 12),
        },
        "hostname": {
            "errors": check_local_hostname()[0],
            "hostname": (subprocess.check_output("hostname", text=True).strip()),
        },
    }
