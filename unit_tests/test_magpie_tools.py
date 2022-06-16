from unittest.mock import (
    patch,
    mock_open,
)

import lib.charms.layer.magpie_tools as magpie_tools
import unit_tests.test_utils


LACP_STATE_SLOW_ACTIVE = '61'
LACP_STATE_FAST_ACTIVE = '63'
LACP_STATE_SLOW_PASSIVE = '60'


def mocked_open_lacp_port_state(actor, partner):
    def the_actual_mock(path):
        if (
            path ==
            "/sys/class/net/test/bonding_slave/ad_actor_oper_port_state"
        ):
            return mock_open(read_data=actor)(path)
        elif (
            path ==
            "/sys/class/net/test/bonding_slave/ad_partner_oper_port_state"
        ):
            return mock_open(read_data=partner)(path)
    return the_actual_mock


class TestMagpieTools(unit_tests.test_utils.CharmTestCase):

    def setUp(self):
        super(TestMagpieTools, self).setUp()
        self.obj = self.tools = magpie_tools
        self.patches = [
            'hookenv']
        self.patch_all()

    def test_safe_status(self):
        self.hookenv.config.return_value = {
            'supress_status': False}
        self.tools.safe_status('active', 'awesome')
        self.hookenv.status_set.assert_called_once_with(
            'active', 'awesome')
        self.hookenv.status_set.reset_mock()
        self.hookenv.config.return_value = {
            'supress_status': True}
        self.tools.safe_status('active', 'awesome')
        self.assertFalse(self.hookenv.status_set.called)

    def test_status_for_speed_check(self):
        self.assertEqual(
            magpie_tools.status_for_speed_check('0', 123, 150),
            ', 123 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('0%', 123, 150),
            ', 123 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check(':P', 123, 150),
            ", invalid min_speed: ':P'"
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('1', 10, 400),
            ', speed ok: 10 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('12', 10, 400),
            ', speed failed: 10 < 12 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('50%', 100, 400),
            ', speed failed: 100 < 200 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('50%', 200, 400),
            ', speed ok: 200 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('50%', 300, 400),
            ', speed ok: 300 mbit/s'
        )
        self.assertEqual(
            magpie_tools.status_for_speed_check('50%', 300, -1),
            ', speed failed: link speed undefined'
        )

    @patch('lib.charms.layer.magpie_tools.open',
           mock_open(read_data=LACP_STATE_SLOW_ACTIVE))
    def test_check_lacp_port_state_match_default(self):
        self.hookenv.config.return_value = {}
        self.assertIsNone(magpie_tools.check_lacp_port_state('test'))

    @patch('lib.charms.layer.magpie_tools.open',
           mock_open(read_data=LACP_STATE_SLOW_ACTIVE))
    def test_check_lacp_port_state_match_explicit_active(self):
        self.hookenv.config.return_value = {'lacp_passive_mode': False}
        self.assertIsNone(magpie_tools.check_lacp_port_state('test'))

    @patch('lib.charms.layer.magpie_tools.open',
           mock_open(read_data=LACP_STATE_SLOW_ACTIVE))
    def test_check_lacp_port_state_match_passive(self):
        self.hookenv.config.return_value = {'lacp_passive_mode': True}
        self.assertIsNone(magpie_tools.check_lacp_port_state('test'))

    @patch('lib.charms.layer.magpie_tools.open')
    def test_check_lacp_port_state_passive_expected_mismatch(self, open_):
        open_.side_effect = mocked_open_lacp_port_state(
            LACP_STATE_SLOW_ACTIVE, LACP_STATE_SLOW_PASSIVE
        )
        self.hookenv.config.return_value = {'lacp_passive_mode': True}
        self.assertIsNone(magpie_tools.check_lacp_port_state('test'))

    @patch('lib.charms.layer.magpie_tools.open')
    def test_check_lacp_port_state_passive_default(self, open_):
        open_.side_effect = mocked_open_lacp_port_state(
            LACP_STATE_SLOW_ACTIVE, LACP_STATE_SLOW_PASSIVE
        )
        self.hookenv.config.return_value = {}
        self.assertEqual(
            magpie_tools.check_lacp_port_state('test'),
            'lacp_port_state_mismatch')

    @patch('lib.charms.layer.magpie_tools.open')
    def test_check_lacp_port_state_passive_configured_active(self, open_):
        open_.side_effect = mocked_open_lacp_port_state(
            LACP_STATE_SLOW_ACTIVE, LACP_STATE_SLOW_PASSIVE
        )
        self.hookenv.config.return_value = {'lacp_passive_mode': False}
        self.assertEqual(
            magpie_tools.check_lacp_port_state('test'),
            'lacp_port_state_mismatch')

    @patch('lib.charms.layer.magpie_tools.open')
    def test_check_lacp_port_state_passive_unexpected_mismatch(self, open_):
        open_.side_effect = mocked_open_lacp_port_state(
            LACP_STATE_FAST_ACTIVE, LACP_STATE_SLOW_PASSIVE
        )
        self.hookenv.config.return_value = {'lacp_passive_mode': True}
        self.assertEqual(
            magpie_tools.check_lacp_port_state('test'),
            'lacp_port_state_mismatch')
