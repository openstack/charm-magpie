# pylint: disable=unused-argument
from charms.reactive import when, when_not
from charmhelpers.core import hookenv
from charms.layer.canary_tools import check_nodes

@when_not('canary.joined')
def no_peers():
    hookenv.status_set('active', 'Waiting for peers to join...')
    
@when('canary.joined')
def check_peers_joined(canary):
    '''
    We do not dismiss joined here so that this check reruns
    every time we do an update-status
    '''

    nodes = canary.get_nodes()
    check_nodes(nodes)

@when('canary.departed')
def check_peers_again(canary):
    '''
    We dismiss departed here so that we don't duplicate checks
    when update-status runs check_peers_joined
    '''
    nodes = canary.get_nodes()
    check_nodes(nodes)
    canary.dismiss_departed()
