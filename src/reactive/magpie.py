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

# pylint: disable=unused-argument
from charms.reactive import when, when_not, set_state, remove_state
from charmhelpers.core import hookenv
from charms.layer.magpie_tools import check_nodes, safe_status, Iperf, Lldp

import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.fetch as fetch


def _set_states(check_result):
    if 'fail' in check_result['icmp']:
        set_state('magpie-icmp.failed')
    else:
        remove_state('magpie-icmp.failed')
    if 'fail' in check_result['dns']:
        set_state('magpie-dns.failed')
    else:
        remove_state('magpie-dns.failed')


@when_not('charm.installed')
def install():
    """Configure APT source.

    The many permutations of package source syntaxes in use does not allow us
    to simply call `add-apt-repository` on the unit and we need to make use
    of `charmhelpers.fetch.add_source` for this to be universally useful.
    """
    source, key = os_utils.get_source_and_pgp_key(
        hookenv.config().get('source', 'distro'))
    fetch.add_source(source, key)
    fetch.apt_update(fatal=True)
    # The ``magpie`` charm is used as principle for functional tests with some
    # subordinate charms.  Install the ``openstack-release`` package when
    # available to allow the functional test code to determine installed UCA
    # versions.
    fetch.apt_install(fetch.filter_installed_packages(['openstack-release']),
                      fatal=False, quiet=True)
    fetch.apt_install(fetch.filter_installed_packages(['iperf']),
                      fatal=True, quiet=True)
    set_state('charm.installed')


@when('charm.installed')
@when_not('lldp.installed')
def install_lldp_pkg():
    if hookenv.config().get('use_lldp'):
        lldp = Lldp()
        lldp.install()
        lldp.enable()
        set_state('lldp.installed')


@when_not('magpie.joined')
def no_peers():
    safe_status('waiting', 'Waiting for peers...')


@when('magpie.joined')
@when_not('leadership.is_leader', 'iperf.checked')
def check_check_state(magpie):
    '''
    Servers should only update their status after iperf has checked them
    '''
    if magpie.get_iperf_checked():
        for units in magpie.get_iperf_checked():
            if units and hookenv.local_unit() in units:
                set_state('iperf.checked')


@when('magpie.joined', 'leadership.is_leader')
@when_not('iperf.servers.ready')
def leader_wait_servers_ready(magpie):
    '''
    Don't do any iperf checks until the servers are listening
    '''
    nodes = sorted(magpie.get_nodes())
    iperf_ready_nodes = sorted(magpie.check_ready_iperf_servers())
    if nodes == iperf_ready_nodes:
        set_state('iperf.servers.ready')
    else:
        remove_state('iperf.servers.ready')


@when('magpie.joined')
@when_not('leadership.is_leader', 'iperf.listening')
def listen_for_checks(magpie):
    '''
    If im not the leader, and im not listening, then listen
    '''
    iperf = Iperf()
    iperf.listen()
    magpie.set_iperf_server_ready()
    set_state('iperf.listening')


@when('iperf.servers.ready', 'magpie.joined', 'leadership.is_leader')
def client_check_hosts(magpie):
    '''
    Once the iperf servers are listening, do the checks
    '''
    nodes = magpie.get_nodes()
    _set_states(check_nodes(nodes, is_leader=True))
    magpie.set_iperf_checked()


@when('magpie.joined', 'iperf.checked')
@when_not('leadership.is_leader')
def check_all_node(magpie):
    '''
    Now that the iperf checks have been done, we can update our status
    '''
    nodes = magpie.get_nodes()
    _set_states(check_nodes(nodes))


@when('prometheus-target.available')
def advertise_metric_port(target):
    '''
    Advertise prometheus metric port used during action execution
    '''
    target.configure(port="8088")
