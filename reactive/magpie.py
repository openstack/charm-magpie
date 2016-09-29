# pylint: disable=unused-argument
from charms.reactive import when, when_not
from charmhelpers.core import hookenv
from charms.layer.magpie_tools import check_nodes

@when_not('magpie.joined')
def no_peers():
    hookenv.status_set('waiting', 'Waiting for peers...')
    
@when('magpie.joined')
def check_peers_joined(magpie):
    '''
    We do not dismiss joined here so that this check reruns
    every time we do an update-status
    '''

    nodes = magpie.get_nodes()
    check_nodes(nodes)

@when('magpie.departed')
def check_peers_again(magpie):
    '''
    We dismiss departed here so that we don't duplicate checks
    when update-status runs check_peers_joined
    '''
    nodes = magpie.get_nodes()
    check_nodes(nodes)
    magpie.dismiss_departed()
