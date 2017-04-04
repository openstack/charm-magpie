# pylint: disable=unused-argument
from charms.reactive import when, when_not, set_state, remove_state
from charms.reactive.bus import get_state
from charmhelpers.core import hookenv
from charms.layer.magpie_tools import check_nodes, safe_status, Iperf, install_iperf
from charmhelpers.core.unitdata import Storage
import threading

def _set_states(check_result):
    if 'fail' in check_result['icmp']:
        set_state('magpie-icmp.failed')
    else:
        remove_state('magpie-icmp.failed')
    if 'fail' in check_result['dns']:
        set_state('magpie-dns.failed')
    else:
        remove_state('magpie-dns.failed')

@when_not('iperf.installed')
def install_iperf_pkg():
    install_iperf()
    set_state('iperf.installed')

@when_not('magpie.joined')
def no_peers():
    safe_status('waiting', 'Waiting for peers...')

@when('magpie.joined')
@when_not('leadership.is_leader', 'iperf.checked')
def check_check_state(magpie):
    '''
    Servers should only update their status after iperf has checked them
    '''
    if (magpie.get_iperf_checked() is not None) and \
            (hookenv.local_unit() in magpie.get_iperf_checked()):
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
    nodes = magpie.get_nodes()
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
    _set_states(check_nodes(nodes, iperf_client=True))
    magpie.set_iperf_checked()

@when('magpie.joined', 'iperf.checked')
@when_not('leadership.is_leader')
def check_all_node(magpie):
    '''
    Now that the iperf checks have been done, we can update our status
    '''
    nodes = magpie.get_nodes()
    _set_states(check_nodes(nodes))

