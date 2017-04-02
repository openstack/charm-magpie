# pylint: disable=unused-argument
from charms.reactive import when, when_not, set_state, remove_state
from charms.reactive.bus import get_state
from charmhelpers.core import hookenv
from charms.layer.magpie_tools import check_nodes, safe_status, Iperf, install_iperf


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

@when('leadership.is_leader', 'magpie.joined')
def manage_iperf_leadership(magpie):
    if magpie.get_iperf_client() is None:
        magpie.set_iperf_client()
        set_state('iperf.client')
    msg = "Manage iperf leadership: {}".format(magpie.get_iperf_client())
    hookenv.log(msg, 'INFO')

#@when('magpie.joined')
#def check_peers_joined(magpie):
#    '''
#    We do not dismiss joined here so that this check reruns
#    every time we do an update-status
#    '''
#    # Am i the client?
#    msg = "FNARRRRGG: The client that i get from the list is: {}".format(magpie.get_iperf_client())
#    hookenv.log(msg, 'INFO')
#    #nodes = magpie.get_nodes()

   
@when('magpie.joined')
@when_not('iperf.servers.ready')
def wait_servers_ready(magpie):
    nodes = magpie.get_nodes()
    iperf_ready_nodes = magpie.check_ready_iperf_servers()
    msg = "All nodes: {}, iperf ready nodes: {}".format(str(nodes), str(iperf_ready_nodes))
    hookenv.log(msg, 'INFO')
    if len(magpie.check_ready_iperf_servers()) == len(magpie.get_nodes()):
        set_state('iperf.servers.ready')
    else:
        remove_state('iperf.servers.ready')

@when('iperf.servers.ready', 'magpie.joined', 'iperf.client')
def client_check_hosts(magpie):
    nodes = magpie.get_nodes()
    iperf_ready_nodes = magpie.check_ready_iperf_servers()
    if iperf_ready_nodes == nodes:
        hookenv.log("_set_states as iperf client")
        _set_states(check_nodes(nodes, iperf_listen=False, iperf_client=True))

@when('magpie.joined')
@when_not('iperf.client', 'iperf.checked')
def listen_for_checks(magpie):
    if magpie.get_iperf_client() is not None:
        msg = "Manage iperf leadership: {}".format(magpie.get_iperf_client())
        hookenv.log(msg, 'INFO')
        nodes = magpie.get_nodes()
        hookenv.log(nodes)
        magpie.set_iperf_server_ready()
        hookenv.log("_set_states as iperf server")
        _set_states(check_nodes(nodes, iperf_listen=True))
        set_state('iperf.checked')
    else:
        hookenv.log("no iperf client selected")

@when('magpie.joined', 'iperf.checked', 'iperf.servers.ready')
def dont_listen(magpie):
    nodes = magpie.get_nodes()
    _set_states(check_nodes(nodes))
