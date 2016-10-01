# pylint: disable=unused-argument
from charms.reactive import when, when_not, set_state, remove_state
from charmhelpers.core import hookenv
from charms.layer.magpie_tools import check_nodes, safe_status


def _set_states(check_result):
    if 'fail' in check_result['icmp']:
        set_state('magpie-icmp.failed')
    else:
        remove_state('magpie-icmp.failed')
    if 'fail' in check_result['dns']:
        set_state('magpie-dns.failed')
    else:
        remove_state('magpie-dns.failed')


@when_not('magpie.joined')
def no_peers():
    safe_status('waiting', 'Waiting for peers...')


@when('magpie.joined')
def check_peers_joined(magpie):
    '''
    We do not dismiss joined here so that this check reruns
    every time we do an update-status
    '''

    nodes = magpie.get_nodes()
    _set_states(check_nodes(nodes))
