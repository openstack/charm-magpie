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

import asyncio
import datetime
import os
import subprocess
import math
import re
import time
import json
import psutil
from charmhelpers.core import hookenv
from charmhelpers.core.host import get_nic_mtu, service_start, service_running
from charmhelpers.fetch import apt_install
import charmhelpers.contrib.network.ip as ch_ip
from prometheus_client import Gauge, start_http_server


class Lldp():
    enabled = False
    parsed_data = None

    def __init__(self):
        self.lldp_out = '/home/ubuntu/lldp_output.' +\
            hookenv.application_name() + '.txt'

    def install(self):
        apt_install("lldpd")

    def disable_i40e_lldp_agent(self):
        path = '/sys/kernel/debug/i40e'
        if os.path.isdir(path):
            hookenv.log('Disabling NIC internal LLDP agent', 'INFO')
            for r, dirs, files in os.walk(path):
                for d in dirs:
                    with open("{}/{}/command".format(path, d), "w") as fh:
                        fh.write('lldp stop')

    def enable(self):
        self.disable_i40e_lldp_agent()
        if not service_running('lldpd'):
            service_start('lldpd')
            hookenv.log('Waiting to collect LLDP data', 'INFO')
            time.sleep(30)

    def collect_data(self):
        cmd = "lldpcli show neighbors details -f json | tee " + self.lldp_out
        os.system(cmd)

    def data(self):
        if not self.parsed_data:
            with open(self.lldp_out, 'r') as f:
                self.parsed_data = json.load(f)
        return self.parsed_data

    def get_interface(self, iface):
        for i in self.data()['lldp']['interface']:
            if iface in i:
                return i[iface]
        return None

    def get_interface_vlan(self, iface):
        try:
            return self.get_interface(iface)['vlan']['vlan-id']
        except (KeyError, TypeError):
            hookenv.log('No LLDP data for {}'.format(iface), 'INFO')
            return None

    def get_interface_port_descr(self, iface):
        try:
            return self.get_interface(iface)['port']['descr']
        except (KeyError, TypeError):
            hookenv.log('No LLDP data for {}'.format(iface), 'INFO')
            return None


class Iperf():
    """
    Install and start a server automatically
    """

    BATCH_CTRL_FILE = '/tmp/batch_hostcheck.ctrl'
    IPERF_BASE_PORT = 5001

    # Dict of prometheus metrics
    metrics = {}

    def __init__(self):
        self.iperf_out = '/home/ubuntu/iperf_output.' + \
            hookenv.application_name() + '.txt'

    def install_iperf(self):
        apt_install("iperf")

    def listen(self, cidr=None, port=None):
        port = port or self.IPERF_BASE_PORT
        if cidr:
            bind_addreess = ch_ip.get_address_in_network(cidr)
        else:
            bind_addreess = (
                hookenv.network_get('magpie')
                ['bind-addresses'][0]['addresses'][0]['address']
            )
        cmd = (
            "iperf -s -fm --port " + str(port) +
            " -B " + bind_addreess + " | tee " +
            self.iperf_out + " &"
        )
        os.system(cmd)

    def speed(self):
        with open(self.iperf_out) as f:
            for line in f.readlines():
                if "bits" in line:
                    match = line
        try:
            return match.rsplit(' ', 2)[1]
        except UnboundLocalError:
            return "no iperf test results: failed"

    def selfcheck(self):
        subprocess.check_output(["iperf", "-c", "localhost", "-t", "1"])

    def hostcheck(self, nodes, iperf_duration):
        # Wait for other nodes to start their servers...
        for node in nodes:
            msg = "checking iperf on {}".format(node[1])
            hookenv.log(msg)
            cmd = "iperf -t {} -c {} -P{}".format(iperf_duration, node[1],
                                                  min(8, self.num_cpus()))
            os.system(cmd)

    def get_increment(self, total_runtime, progression):
        return datetime.timedelta(
            minutes=math.ceil(total_runtime / len(progression)))

    def get_plan(self, progression, increment):
        now = datetime.datetime.now()
        plan = []
        for i in enumerate(progression):
            start_time = now + (i[0] * increment)
            plan.append((start_time, i[1]))
        return plan

    def num_cpus(self):
        '''
        Compatibility wrapper for calculating the number of CPU's
        a unit has.

        @returns: int: number of CPU cores detected
        '''
        try:
            return psutil.cpu_count()
        except AttributeError:
            return psutil.NUM_CPUS

    def update_plan(self, plan, skip_to, increment):
        progression = []
        for (_time, conc) in plan:
            if conc >= skip_to:
                progression.append(conc)
        return self.get_plan(progression, increment)

    def get_concurrency(self, plan):
        now = datetime.datetime.now()
        for (_time, conc) in reversed(plan):
            if _time < now:
                return conc

    def wipe_batch_ctrl_file(self):
        with open(self.BATCH_CTRL_FILE, "w") as ctrl_file:
            ctrl_file.truncate(0)

    def read_batch_ctrl_file(self):
        with open(self.BATCH_CTRL_FILE, 'r') as ctrl_file:
            contents = ctrl_file.read()
        return contents

    def add_iperf_bandwidth_metric(self, src_unit, dst_unit, value, tag):
        """
        labels:
            fio_{read|write}_{iops,bandwidth,latency}
            rbd_bench_{read|write}_??
            rados_bench_{read|write}_??
        """
        if 'magpie_iperf_bandwidth' not in self.metrics:
            self.metrics['magpie_iperf_bandwidth'] = Gauge(
                'magpie_iperf_bandwidth',
                'magpie iperf bandwidth (bits/s)',
                ['model', 'src', 'dest', 'tag']
            )
        self.metrics['magpie_iperf_bandwidth'].labels(
            model=hookenv.model_name(),
            src=src_unit, dest=dst_unit,
            tag=tag).set(value)

    def add_iperf_concurrency_metric(self, src_unit, dst_unit, value, tag):
        if 'magpie_iperf_concurrency' not in self.metrics:
            self.metrics['magpie_iperf_concurrency'] = Gauge(
                'magpie_iperf_concurrency',
                'magpie iperf process concurrency',
                ['model', 'src', 'dest', 'tag']
            )
        self.metrics['magpie_iperf_concurrency'].labels(
            model=hookenv.model_name(),
            src=src_unit, dest=dst_unit,
            tag=tag).set(value)

    def process_results(self, results, nodes, concurrency, tag):
        bandwidth = {ip: 0 for ip in nodes.keys()}
        src_unit = hookenv.local_unit().replace('/', '_')
        for result in results:
            bandwidth[result['dest_ip']] += math.ceil(
                int(result['bits_per_second']))
        for ip, node_name in nodes.items():
            dst_unit = node_name.replace('/', '_')
            self.add_iperf_bandwidth_metric(
                src_unit,
                dst_unit,
                bandwidth[ip],
                tag)
            self.add_iperf_concurrency_metric(
                src_unit,
                dst_unit,
                concurrency,
                tag)

    def batch_hostcheck(self, nodes, total_runtime, iperf_batch_time=None,
                        progression=None, tag='default'):
        iperf_batch_time = iperf_batch_time or 60
        progression = progression or [4, 8, 16, 24, 32, 40]
        increment = self.get_increment(total_runtime, progression)
        plan = self.get_plan(progression, increment)
        finish_time = datetime.datetime.now() + datetime.timedelta(
            minutes=total_runtime)

        self.wipe_batch_ctrl_file()
        action_output = []

        # Prometheus target for scraping of collected FIO metrics
        start_http_server(8088)

        while datetime.datetime.now() < finish_time:

            async def run(cmd):
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)

                stdout, stderr = await proc.communicate()

                if stdout:
                    return stdout.decode()
                if stderr:
                    print('[stderr]')
                    print(stderr.decode())

            async def run_iperf(node_name, ip, iperf_batch_time,
                                concurrency, port='5001',
                                tag='default'):
                node_name = node_name.replace('/', '_')
                cmd = "iperf -t{} -c {} --port {} -P{} --reportstyle c".format(
                    iperf_batch_time,
                    ip,
                    port,
                    concurrency)
                hookenv.log(cmd, 'INFO')
                out = await run(cmd)
                if out:
                    out = out.splitlines()[-1]
                    out = out.rstrip().split(',')
                    results = {
                        'timestamp': out[0],
                        'src_ip': out[1],
                        'src_port': out[2],
                        'dest_ip': out[3],
                        'dest_port': out[4],
                        'unknown1': out[5],
                        'time_interval': out[6],
                        'transferred_bytes': out[7],
                        'bits_per_second': out[8],
                    }
                    hookenv.log(
                        'Destination: {}:{} ({} MB, {} Mbps)'.format(
                            out[3], out[4],
                            int(int(out[7]) / 1024 / 1024),
                            int(int(out[8]) / 1024 / 1024)),
                        'INFO'
                    )
                    return results
                return {}

            async def run_iperf_batch(concurrency, nodes,
                                      iperf_batch_time,
                                      tag='default'):
                results = await asyncio.gather(
                    *[run_iperf(node_name, ip, iperf_batch_time,
                                concurrency, tag=tag)
                      for ip, node_name, in nodes.items()])
                self.process_results(results, nodes, concurrency, tag)
                return results

            contents = self.read_batch_ctrl_file()
            if contents:
                try:
                    plan = self.update_plan(plan, int(contents), increment)
                    self.wipe_batch_ctrl_file()
                except ValueError:
                    pass
            concurrency = self.get_concurrency(plan)
            hookenv.status_set(
                'active',
                'Concurrency: {} Nodes: {}'.format(
                    concurrency,
                    ', '.join([i[0] for i in nodes])))
            loop = asyncio.get_event_loop()
            results = loop.run_until_complete(
                run_iperf_batch(
                    concurrency,
                    nodes,
                    iperf_batch_time,
                    tag=tag))
            action_output.append(results)
        return action_output


def safe_status(workload, status):
    cfg = hookenv.config()
    if not cfg.get('supress_status'):
        hookenv.status_set(workload, status)


def ping(addr, timeout, count, interval, mtu=None) -> int:
    """
    Ping `addr` with provided options.

    Return an integer between 0 and 100,
    representing the percentage of packet loss.

    :param addr: ip address or hostname to ping
    :type addr: str
    :param timeout: timeout in seconds per icmp request
    :type timeout: Union[str, int, float]
    :param count: number of packets to send
    :type count: Union[str, int]
    :param interval: seconds between sending each packet
    :type interval: Union[str, int, float]
    :param mtu: optional packet size to send
    :type mtu: Union[str, int, None]
    :returns: an integer between 0 and 100
    :rtype: int
    """
    args = [
        "ping",
        "-c", str(count),
        "-i", str(interval),
        "-W", str(timeout),
    ]
    if mtu:
        args.extend(("-M", "do", "-s", str(int(mtu) - 28)))
    args.append(addr)
    hookenv.log('Ping command: {}'.format(" ".join(args)), hookenv.DEBUG)
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    match = re.search(
        r"(\d+)(?:\.\d+)?%\s+packet\s+loss",
        proc.stdout.decode()
    )
    if match:
        return int(match.group(1))
    hookenv.log(
        f"pinging {addr} failed with output: '{proc.stdout}'",
        hookenv.DEBUG
    )
    return 100


def check_local_hostname():
    local_hostname = subprocess.check_output('hostname', shell=True)\
        .decode('utf-8').rstrip()
    lookup_cmd = "getent hosts {}".format(local_hostname)
    hookenv.log('Looking up local hostname: {}'.format(local_hostname))
    try:
        result = subprocess.check_output(lookup_cmd, shell=True)\
            .decode('utf-8').rstrip()
        result = ''
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = local_hostname
        stderr = exc.returncode
    return result, stderr


def check_local_mtu(required_mtu, iface_mtu):
    if required_mtu == 0:
        return 0
    elif 0 <= (int(iface_mtu) - int(required_mtu)) <= 12:
        return 100
    else:
        return 200


def status_for_speed_check(min_speed, speed, link_speed):
    """
    Generate and return a portion of the status line for the iperf speed test.

    :param min_speed: raw value of min-speed from charm config
    :type min_speed: str
    :param speed: speed in mbit/s from iperf
    :type speed: float
    :param link_speed: link speed in mbit/s
    :type link_speed: int
    """
    if not re.match(r'^\d+%?$', min_speed):
        return ', invalid min_speed: {!r}'.format(min_speed)

    if int(min_speed.rstrip('%')) == 0:
        return ', {} mbit/s'.format(speed)

    if '%' in min_speed:
        # virtual link with no defined speed
        if link_speed < 0:
            hookenv.log(
                'link speed negative, so unable to '
                'calculate value for min_speed percentage',
                'INFO'
            )
            return ', speed failed: link speed undefined'

        # convert percentage to integer mbit/s
        min_speed = int(min_speed.rstrip('%')) * link_speed // 100
    else:
        min_speed = int(min_speed)

    if min_speed <= speed:
        return ', speed ok: {} mbit/s'.format(speed)
    else:
        return ', speed failed: {} < {} mbit/s'.format(speed, min_speed)


def check_port_description(lldp):
    iface_dir = "/sys/class/net"
    status = None
    local_hostname = subprocess.check_output('hostname', shell=True)\
        .decode('utf-8').rstrip()
    for r, dirs, files in os.walk(iface_dir):
        for d in dirs:
            if d == 'lo':
                continue
            if d.startswith('vnet'):
                continue
            if d.startswith('veth'):
                continue
            if check_iface_type(d) == 'eth':
                if not check_iface_down(d):
                    desc = lldp.get_interface_port_descr(d)
                    hookenv.log("Port {} description {}".format(d, desc),
                                'INFO')
                    if desc:
                        if not re.search(local_hostname, desc):
                            if status:
                                status = "{} {}:{}"\
                                    .format(status, d, desc)
                            else:
                                status = "{}:{}".format(d, desc)
    if status:
        return "ports failed: {}".format(status)
    else:
        return "ports ok"


def check_iface_type(iface):
    iface_dir = "/sys/class/net/{}".format(iface)
    with open("{}/uevent".format(iface_dir)) as fos:
        content = fos.read()
        if re.search('DEVTYPE', content):
            return "complex"
    return 'eth'


def check_iface_down(iface):
    iface_dir = "/sys/class/net/{}".format(iface)
    with open("{}/operstate".format(iface_dir)) as fos:
        content = fos.read()
        if not re.search('up', content):
            return "down"
    with open("{}/carrier".format(iface_dir)) as fos:
        content = fos.read()
        if not re.search('1', content):
            return "down"
    return None


def check_aggregator_id(bond_iface, slave_iface):
    bond_iface_dir = "/sys/class/net/{}/bonding".format(bond_iface)
    slave_iface_dir = "/sys/class/net/{}/bonding_slave".format(slave_iface)
    with open("{}/ad_aggregator".format(bond_iface_dir)) as fos:
        bond_aggr_value = fos.read()
    with open("{}/ad_aggregator_id".format(slave_iface_dir)) as fos:
        slave_aggr_value = fos.read()
    if bond_aggr_value != slave_aggr_value:
        return "aggregate_id_mismatch"
    return None


def check_lacp_port_state(iface):
    iface_dir = "/sys/class/net/{}/bonding_slave".format(iface)
    with open("{}/ad_actor_oper_port_state".format(iface_dir)) as fos:
        actor_port_state = fos.read()
    with open("{}/ad_partner_oper_port_state".format(iface_dir)) as fos:
        partner_port_state = fos.read()
    if actor_port_state != partner_port_state:
        return "lacp_port_state_mismatch"
    return None


def get_bond_mode(bond):
    bond_path = "/sys/class/net/{}".format(bond)
    with open("{}/bonding/mode".format(bond_path)) as fos:
        content = fos.read()
        if re.search('balance-rr', content):
            return "balance_rr"
        elif re.search('active-backup', content):
            return "active_backup"
        elif re.search('balance-xor', content):
            return "balance_xor"
        elif re.search('broadcast', content):
            return "broadcast"
        elif re.search('802.3ad', content):
            return "lacp"
        elif re.search('balance-tlb', content):
            return "balance_tlb"
        elif re.search('balance-alb', content):
            return "balance_alb"
    return 'others'


def check_bond(bond, lldp=None):
    bond_path = "/sys/class/net/{}".format(bond)
    if not os.path.isdir(bond_path):
        return "missing"
    if check_iface_down(bond):
        return "down"
    with open("{}/bonding/slaves".format(bond_path)) as fos:
        content = fos.read()
        vlan = None
        for slave in content.split():
            if check_iface_down(slave):
                return "{} down".format(slave)
            if lldp:
                if vlan:
                    if not vlan == lldp.get_interface_vlan(slave):
                        return "vlan mismatch"
                else:
                    vlan = lldp.get_interface_vlan(slave)
        if get_bond_mode(bond) == "lacp":
            for slave in content.split():
                if check_aggregator_id(bond, slave):
                    return "Aggregator ID mismatch"
            for slave in content.split():
                if check_lacp_port_state(slave):
                    return "LACP port state mismatch"
    return None


def check_bonds(bonds, lldp=None):
    bonds_status = None
    for bond in [b.strip() for b in bonds.split(',')]:
        bond_status = check_bond(bond, lldp)
        if bond_status:
            if bonds_status:
                bonds_status = "{} {}:{}\
                        ".format(bonds_status, bond, bond_status)
            else:
                bonds_status = "{}:{}".format(bond, bond_status)
    if bonds_status:
        return "bonds failed: {}".format(bonds_status)
    else:
        return "bonds ok"


def get_link_speed(iface):
    with open('/sys/class/net/{}/speed'.format(iface)) as f:
        return int(f.read())


def check_nodes(nodes, iperf_client=False):
    cfg = hookenv.config()
    local_ip = hookenv.network_get("magpie")['ingress-addresses'][0]
    iface_lines = subprocess.check_output(["ip", "route", "show", "to",
                                           "match", local_ip]).decode()
    iface_lines = iface_lines.split('\n')
    for line in iface_lines:
        if re.match('.* via .*', line) is None:
            break
    primary_iface = str(line).split('dev')[1].split(' ')[1]
    iface_mtu = get_nic_mtu(primary_iface)
    link_speed = get_link_speed(primary_iface)
    required_mtu = cfg.get('required_mtu')
    min_speed = cfg.get('min_speed')
    msg = "MTU for iface: {} is {}".format(primary_iface, iface_mtu)
    hookenv.log(msg, 'INFO')
    port_status = ""
    lldp = None
    if cfg.get('use_lldp'):
        lldp = Lldp()
        lldp.enable()
        lldp.collect_data()
        if cfg.get('check_port_description'):
            port_status = "{}, ".format(check_port_description(lldp))
    cfg_check_bonds = cfg.get('check_bonds', lldp)
    # Attempt to find the bond interfaces and create a comma-delimited
    # string out of them for use by the check_bonds() call below.
    all_bonds_path = "/sys/class/net/bonding_masters"
    if cfg_check_bonds.upper() == "AUTO" and os.path.exists(all_bonds_path):
        with open(all_bonds_path) as fos:
            all_bonds = fos.read()
            if all_bonds:
                cfg_check_bonds = all_bonds.replace(' ', ',')
    elif cfg_check_bonds.upper() == "AUTO":
        hookenv.log('No bond interfaces available.', 'DEBUG')
        cfg_check_bonds = ""
    bond_status = ""
    # Perform actual bond checking
    if cfg_check_bonds:
        bond_status = "{}, ".format(check_bonds(cfg_check_bonds, lldp))
    cfg_check_iperf = cfg.get('check_iperf')
    if cfg_check_iperf:
        hookenv.log("Running iperf test", 'INFO')
        if not iperf_client:
            iperf = Iperf()

            no_ping_mtu = check_ping(nodes, mtu=required_mtu or iface_mtu)
            if not no_ping_mtu:
                mtu = required_mtu or iface_mtu
            else:
                mtu = 'failed'

            speed = iperf.speed()
            # Make space for 8 or 12 byte variable overhead (TCP options)
            if "failed" not in str(mtu):
                if 0 <= (int(iface_mtu) - int(mtu)) <= 12:
                    iperf_status = ", net mtu ok: {}".format(iface_mtu)
                else:
                    iperf_status = ", net mtu failed, mismatch: {} packet vs {}\
                    on iface {}".format(mtu, iface_mtu, primary_iface)
            else:
                iperf_status = ", network mtu check failed"
            if "failed" not in speed:
                iperf_status += status_for_speed_check(
                    min_speed, float(speed), link_speed)
            else:
                iperf_status = iperf_status + ", iperf speed check failed"
        elif iperf_client:
            iperf_status = ", iperf leader, mtu: {}".format(iface_mtu)
            iperf = Iperf()
            cfg_iperf_duration = cfg.get('iperf_duration')
            iperf.hostcheck(nodes, cfg_iperf_duration)
    else:
        iperf_status = ""
    if check_local_mtu(required_mtu, iface_mtu) == 100:
        iperf_status = iperf_status + ", local mtu ok, required: \
            {}".format(required_mtu)
    elif check_local_mtu(required_mtu, iface_mtu) == 200:
        iperf_status = iperf_status + ", local mtu failed, \
        required: {}, iface: {}".format(required_mtu, iface_mtu)
    hookenv.log('doing other things after iperf', 'INFO')
    cfg_check_local_hostname = cfg.get('check_local_hostname')
    if cfg_check_local_hostname:
        no_hostname = check_local_hostname()
        local_hostname = subprocess.check_output(
            'hostname', shell=True).decode('utf-8').rstrip()
        if no_hostname[0] == '':
            no_hostname = ', local hostname ok ({})'.format(local_hostname)
            hookenv.log('Local hostname lookup OK: {}'.format(
                str(no_hostname)), 'INFO')
        else:
            no_hostname = ', local hostname failed ({})'.format(local_hostname)
            hookenv.log('Local hostname lookup FAILED: {}'.format(
                str(no_hostname)), 'ERROR')

    no_ping = check_ping(nodes)
    cfg_check_dns = cfg.get('check_dns')
    if cfg_check_dns:
        no_dns = check_dns(nodes)
        hookenv.log("Units with DNS problems: " + str(no_dns))
        try:
            dns_status
        except NameError:
            dns_status = ''
    else:
        dns_status = ''
        no_dns = ([], [], [])
    try:
        dns_status
    except NameError:
        dns_status = ''

    if not no_ping:
        no_ping = 'icmp ok'
    else:
        no_ping = 'icmp failed: ' + str(no_ping)

    if no_dns == ([], [], []):
        dns_status = ', dns ok'
    else:
        no_rev = no_dns[0]
        no_fwd = no_dns[1]
        no_match = no_dns[2]
        if no_match != []:
            dns_status = ', match dns failed: ' + str(no_match)
        else:
            if no_rev:
                no_rev = ', rev dns failed: ' + str(no_rev)
            if no_fwd:
                no_fwd = ', fwd dns failed: ' + str(no_fwd)
        if no_rev == []:
            no_rev = ''
        if no_fwd == []:
            no_fwd = ''
        dns_status = '{}{}{}'\
            .format(dns_status, str(no_rev), str(no_fwd))

    if cfg_check_local_hostname:
        check_status = '{}{}{}{}{}{}'.format(
            port_status, bond_status, no_ping,
            str(no_hostname), str(dns_status), str(iperf_status))
    else:
        check_status = '{}{}{}{}{}'.format(
            port_status, bond_status, no_ping,
            str(dns_status), str(iperf_status))

    if 'failed' in check_status:
        workload = 'blocked'
    else:
        workload = 'active'
    safe_status(workload, check_status)
    reactive_state = {'icmp': no_ping, 'dns': dns_status}
    return reactive_state


def check_ping(nodes, mtu=None):
    """
    Ping nodes and return list of unreachable unit ids.

    :param mtu: optional packet size to send
    :type mtu: Union[str, int, None]
    :returns: a list of unreachable unit ids.
    :rtype: List[str]
    """
    cfg = hookenv.config()
    ping_timeout = cfg.get('ping_timeout')
    ping_tries = cfg.get('ping_tries')
    ping_interval = cfg.get('ping_interval')
    unreachable = []
    for node in nodes:
        unit_id = node[0].split('/')[1]
        hookenv.log('Pinging unit_id: ' + str(unit_id), 'INFO')
        packet_loss = ping(node[1], ping_timeout, ping_tries,
                           ping_interval, mtu=mtu)
        if packet_loss > 0:
            hookenv.log(
                f'Ping FAILED for unit_id: {unit_id}.  '
                f'{packet_loss}% packet loss',
                hookenv.ERROR
            )
            unreachable.append(f"{unit_id}: {packet_loss}% packet loss")
        else:
            hookenv.log(
                f'Ping OK for unit_id: {unit_id}.  '
                f'{packet_loss}% packet loss',
                hookenv.INFO
            )

    return unreachable


def check_dns(nodes):
    cfg = hookenv.config()
    dns_server = cfg.get('dns_server')
    dns_tries = cfg.get('dns_tries')
    dns_time = cfg.get('dns_time')
    try:
        norev
    except NameError:
        norev = []
    try:
        nofwd
    except NameError:
        nofwd = []
    try:
        nomatch
    except NameError:
        nomatch = []
    hookenv.log("DNS (ALL NODES): {}".format(nodes))
    for node in nodes:
        ip = node[1]
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            hookenv.log("private-address appears to be a hostname: {},"
                        " attempting forward lookup...", 'WARN')
            ip = forward_dns(ip, dns_server, dns_tries, dns_time)[0]
        else:
            hookenv.log('private-address appears to be an IP', 'INFO')
        unit_id = node[0].split('/')[1]
        hookenv.log("Reverse lookup for ip: {}, node: {},"
                    " unit_id: {}".format(ip, node[0], unit_id), 'INFO')
        reverse, r_stderr = reverse_dns(ip, dns_server, dns_tries, dns_time)
        hookenv.log("Reverse result for unit_id: {}, hostname: {},"
                    " exitcode: {}".format(unit_id, str(reverse),
                                           str(r_stderr)))
        if r_stderr:
            hookenv.log("Reverse FAILED for"
                        " unit_id: {}".format(unit_id), 'ERROR')
            if unit_id not in norev:
                norev.append(unit_id)
            continue
        else:
            hookenv.log("Reverse OK for unit_id: {}".format(unit_id), 'INFO')
            if unit_id in norev:
                norev.remove(unit_id)
            hookenv.log("Forward lookup for hostname: {}, node: {},"
                        " unit_id: {}".format(str(reverse), node[0], unit_id),
                        'INFO')
            for rev in reverse.split():
                forward, f_stderr = forward_dns(rev, dns_server,
                                                dns_tries, dns_time)
                hookenv.log("Forward result for unit_id: {}, ip: {},"
                            " exitcode: {}".format(unit_id, forward,
                                                   str(f_stderr)))
                if f_stderr:
                    hookenv.log("Forward FAILED for"
                                " unit_id: {}".format(unit_id), 'ERROR')
                    if unit_id not in nofwd:
                        nofwd.append(unit_id)
                else:
                    hookenv.log("Forward OK for"
                                " unit_id: {}".format(unit_id), 'INFO')
                    if unit_id in nofwd:
                        nofwd.remove(unit_id)
                    if ip != forward:
                        mstr = r'(r\"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")'
                        if not re.match(mstr, forward):
                            forward = "Can not resolve hostname to IP {}"\
                                      .format(repr(forward))
                        hookenv.log("Original IP and Forward MATCH FAILED for"
                                    " unit_id: {}, Original: {}, Forward: {}"
                                    .format(unit_id, ip, forward), 'ERROR')
                        if unit_id not in nomatch:
                            nomatch.append(unit_id)
                    else:
                        hookenv.log("Original IP and Forward MATCH OK for \
                                    unit_id: {}, Original: {}, Forward: {}"
                                    .format(unit_id, ip, forward),
                                    'INFO')
                        if unit_id in nomatch:
                            nomatch.remove(unit_id)
                        break

    return norev, nofwd, nomatch


def reverse_dns(input, dns_server, tries, timeout):
    cmd = '/usr/bin/dig -x ' + input + ' +short +tries={} +time={}'\
        .format(tries, timeout)
    if dns_server:
        cmd = '{} @{}'.format(cmd, dns_server)
    hookenv.log('DNS Reverse command: {}'.format(cmd), 'DEBUG')
    try:
        result = subprocess.check_output(cmd, shell=True)\
            .decode('utf-8').rstrip()
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = "Reverse DNS lookup error: " + str(exc.output)
        stderr = exc.returncode
    if result == '':
        result = 'No reverse response'
        stderr = 1
    return result, stderr


def forward_dns(input, dns_server, tries, timeout):
    cmd = '/usr/bin/dig ' + input + ' +short +tries={} +time={}'\
        .format(tries, timeout)
    if dns_server:
        cmd = '{} @{}'.format(cmd, dns_server)
    hookenv.log('DNS Forward command: {}'.format(cmd), 'DEBUG')
    try:
        result = subprocess.check_output(cmd, shell=True)\
            .decode('utf-8').rstrip()
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = "Forward DNS lookup error: " + str(exc.output)
        stderr = exc.returncode
    if result == '':
        result = 'No forward response'
        stderr = 1
    return result, stderr
