# pylint: disable=unused-argument
from charms.reactive import when, when_not, when_not_all, is_state
from charmhelpers.core import hookenv
from charms import layer
from charms.layer.canary_tools import check_nodes

@when_not('canary.joined')
def no_peers():
    hookenv.status_set('active', 'Waiting for peers to join...')
    
@when('canary.joined')
def check_peers(canary):
    '''
    Need to decide if active is ok for status
    and what to do if a unit is unreachable
    '''

    nodes = canary.get_nodes()
    check_nodes(nodes)
