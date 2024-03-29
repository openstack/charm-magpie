from unittest.mock import (
    patch,
    mock_open,
    MagicMock,
)

import lib.charms.layer.magpie_tools as magpie_tools
from unit_tests.test_utils import patch_open, CharmTestCase, async_test
import netifaces

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


class TestMagpieTools(CharmTestCase):

    def setUp(self):
        super(TestMagpieTools, self).setUp()
        self.obj = self.tools = magpie_tools
        self.patches = [
            'hookenv',
        ]
        self.patch_all()
        self.maxDiff = None

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

    def test_get_link_speed(self):
        # Normal operation
        with patch_open() as (mock_open, mock_file):
            mock_file.read.return_value = b'1000'
            self.assertEqual(
                1000,
                magpie_tools.get_link_speed('eth0'),
            )
            mock_open.assert_called_once_with('/sys/class/net/eth0/speed')
        # Invalid argument
        with patch_open() as (mock_open, mock_file):
            mock_open.side_effect = OSError()
            self.assertEqual(
                -1,
                magpie_tools.get_link_speed('eth0'),
            )

    @async_test
    @patch(
        "lib.charms.layer.magpie_tools.get_iface_mac",
        lambda _: "de:ad:be:ef:01:01"
    )
    @patch(
        "lib.charms.layer.magpie_tools.get_dest_mac",
        lambda _, __: "de:ad:be:ef:02:02"
    )
    @patch(
        "lib.charms.layer.magpie_tools.ch_ip.get_iface_from_addr",
        lambda _: "de:ad:be:ef:03:03"
    )
    @patch(
        "lib.charms.layer.magpie_tools.get_src_ip_from_dest",
        lambda _: "192.168.2.2"
    )
    @patch("lib.charms.layer.magpie_tools.run")
    async def test_run_iperf(self, mock_run):

        async def mocked_run(cmd):
            return """
19700101000000,192.168.2.2,60266,192.168.2.1,5001,2,0.0-10.1,95158332,75301087
19700101000000,192.168.2.2,60268,192.168.2.1,5001,1,0.0-10.1,61742908,27989222
"""

        mock_run.side_effect = mocked_run
        result = await magpie_tools.run_iperf(
            "mynode", "192.168.2.1", "10", "2"
        )

        mock_run.assert_called_once_with(
            "iperf -t10 -c 192.168.2.1 --port 5001 -P2 --reportstyle c"
        )
        self.assertEqual(result, {
            "GBytes_transferred": 0.146,
            "Mbits_per_second": 98,
            "bits_per_second": 103290309,
            "concurrency": "2",
            "dest_ip": "192.168.2.1",
            "dest_node": "mynode",
            "dest_port": "5001",
            "session": [2, 1],
            "src_ip": "192.168.2.2",
            "src_port": [60266, 60268],
            "time_interval": "0.0-10.1",
            "timestamp": "19700101000000",
            "transferred_bytes": 156901240,
            "src_mac": "de:ad:be:ef:01:01",
            "dest_mac": "de:ad:be:ef:02:02",
            "src_interface": "de:ad:be:ef:03:03",
        })

    @patch('netifaces.AF_LINK', 17)
    @patch.object(netifaces, 'ifaddresses')
    @patch.object(netifaces, 'interfaces')
    def test_get_iface_mac(self, mock_interfaces, mock_addresses):
        mock_interfaces.return_value = [
            'lo',
            'enp0s31f6',
            'eth0',
            'bond0',
            'br0'
        ]
        mock_addresses.return_value = {
            17: [{'addr': 'c8:5b:76:80:86:01'}],
            2: [{'addr': '192.168.123.45', 'netmask': '255.255.255.0'}],
        }

        # with interface listed by netifaces
        self.assertEqual(
            magpie_tools.get_iface_mac('bond0'),
            'c8:5b:76:80:86:01',
        )
        # with unknown interface
        self.assertEqual(
            '',
            magpie_tools.get_iface_mac('wronginterface0')
        )

    @patch('subprocess.PIPE', None)
    @patch('subprocess.run')
    def test_get_dest_mac(self, mock_subprocess):
        mock_stdout = MagicMock()
        mock_stdout.configure_mock(
            **{
                'stdout.decode.return_value': '[{"dst":"192.168.12.1",'
                '"lladdr":"dc:fb:02:d1:28:18","state":["REACHABLE"]}]'
            }
        )
        mock_subprocess.return_value = mock_stdout
        self.assertEqual(
            magpie_tools.get_dest_mac("eth0", "192.168.12.1"),
            'dc:fb:02:d1:28:18',
        )

    @patch('subprocess.PIPE', None)
    @patch('subprocess.run')
    def test_get_src_ip_from_dest(self, mock_subprocess):
        mock_stdout = MagicMock()
        mock_stdout.configure_mock(
            **{
                'stdout.decode.return_value': '[{"dst":"192.168.12.1",'
                '"dev":"enp5s0","prefsrc":"192.168.12.15","flags":[],'
                '"uid":1000,"cache":[]}]'
            }
        )
        mock_subprocess.return_value = mock_stdout
        self.assertEqual(
            magpie_tools.get_src_ip_from_dest("192.168.12.1"),
            '192.168.12.15',
        )

    def test_parse_dig_yaml(self):
        output = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - 99.0.0.10.in-addr.arpa. 30 IN PTR example.com.
        """
        result, stderr = magpie_tools.parse_dig_yaml(
            output,
            "",
            1,
            30,
            is_reverse_query=True,
        )
        self.assertEqual(result, 'example.com')
        self.assertEqual(stderr, 0)

    @patch('subprocess.check_output')
    def test_parse_dig_yaml_calls_resolves_cname(self, mock_subprocess):
        output = "-\n  type: MESSAGE\n"
        output += "  message:\n"
        output += "    response_message_data:\n"
        output += "      ANSWER_SECTION:\n"
        output += "        - 99.0.0.10.in-addr.arpa. 30 IN CNAME"
        output += " 99.1-25.0.0.10.in-addr.arpa"

        rev_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - 99.0.0.10.in-addr.arpa. 30 IN PTR example.com.
        """
        mock_subprocess.side_effect = [
            bytes(rev_response, "utf-8")
        ]
        result, stderr = magpie_tools.parse_dig_yaml(
            output,
            "",
            1,
            30,
            is_reverse_query=True,
        )
        self.assertEqual(result, 'example.com')
        self.assertEqual(stderr, 0)

    @patch('subprocess.check_output')
    def test_forward_dns_good(self, mock_subprocess):
        ip = "10.0.0.99"
        unit_id = "magpie/0"
        self.hookenv.config.return_value = {
            "dns_server": "127.0.0.1",
            "dns_tries": "1",
            "dns_time": "3"
        }
        rev_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - 99.0.0.10.in-addr.arpa. 30 IN PTR example.com.
        """
        fwd_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - example.com. 30 IN A 10.0.0.99
        """
        mock_subprocess.side_effect = [
            bytes(rev_response, "utf-8"),  # for reverse_dns
            bytes(fwd_response, "utf-8")  # for forward_dns
        ]
        norev, nofwd, nomatch = magpie_tools.check_dns([(unit_id, ip)])
        self.assertEqual(
            norev, [], "Reverse lookup failed for IP {}".format(ip))
        self.assertEqual(
            nofwd, [], ("Forward lookup failed for IP {}, "
                        "faked to example.com".format(ip)))
        self.assertEqual(
            nomatch, [], "Reverse and forward lookups didn't match")

    @patch('subprocess.check_output')
    def test_forward_dns_multiple_ips(self, mock_subprocess):
        ip = "10.0.0.99"
        unit_id = "magpie/0"
        self.hookenv.config.return_value = {
            "dns_server": "127.0.0.1",
            "dns_tries": "1",
            "dns_time": "3"
        }
        rev_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - 99.0.0.10.in-addr.arpa. 30 IN PTR example.com.
        """
        fwd_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - example.com. 30 IN A 10.0.0.99
                - example.com. 30 IN A 10.1.0.99
                - example.com. 30 IN A 10.2.0.99
        """
        mock_subprocess.side_effect = [
            bytes(rev_response, "utf-8"),  # for reverse_dns
            bytes(fwd_response, "utf-8")  # for forward_dns
        ]
        norev, nofwd, nomatch = magpie_tools.check_dns([(unit_id, ip)])
        self.assertEqual(
            norev, [], "Reverse lookup failed for IP {}".format(ip))
        self.assertEqual(
            nofwd, [], ("Forward lookup failed for IP {}, "
                        "faked to example.com".format(ip))
        )
        self.assertEqual(
            nomatch, [], "Reverse and forward lookups didn't match")
        self.hookenv.log.assert_any_call(
            "Forward result for unit_id: 0, "
            "ip: 10.0.0.99\n10.1.0.99\n10.2.0.99, exitcode: 0"
        )
        self.hookenv.log.assert_any_call(
            "Original IP and Forward MATCH OK for unit_id: 0, "
            "Original: 10.0.0.99, "
            "Forward: ['10.0.0.99', '10.1.0.99', '10.2.0.99']", "INFO"
        )

    @patch('subprocess.check_output')
    def test_cname_dns_is_followed(self, mock_subprocess):
        ip = "10.0.0.99"
        unit_id = "magpie/0"
        self.hookenv.config.return_value = {
            "dns_server": "127.0.0.1",
            "dns_tries": "1",
            "dns_time": "3",
        }
        rev_response = "-\n"
        rev_response += "  type: MESSAGE\n"
        rev_response += "  message:\n"
        rev_response += "    response_message_data:\n"
        rev_response += "      ANSWER_SECTION:\n"
        rev_response += "        - 99.0.0.10.in-addr.arpa. 30 IN CNAME"
        rev_response += " 99.1-25.0.0.10.in-addr.arpa."
        cname_response = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - 99.0-25.0.10.in-addr.arpa. 30 IN PTR example.com.
                - 99.0-25.0.10.in-addr.arpa. 30 IN PTR other.example.com.
        """
        fwd_response_1 = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - example.com. 30 IN A 10.0.0.99
        """
        fwd_response_2 = """
        -
          type: MESSAGE
          message:
            response_message_data:
              ANSWER_SECTION:
                - other.example.com. 30 IN A 10.0.0.99
        """
        mock_subprocess.side_effect = [
            bytes(rev_response, "utf-8"),  # for reverse_dns
            bytes(cname_response, "utf-8"),  # for resolve_cname
            bytes(fwd_response_1, "utf-8"),  # for forward_dns
            bytes(fwd_response_2, "utf-8")  # for forward_dns
        ]
        norev, nofwd, nomatch = magpie_tools.check_dns([(unit_id, ip)])
        self.assertEqual(
            norev, [], "Reverse lookup failed for IP {}".format(ip))
        self.assertEqual(
            nofwd, [], ("Forward lookup failed for IP {}, "
                        "faked to example.com".format(ip))
        )
        self.assertEqual(
            nomatch, [], "Reverse and forward lookups didn't match")
        self.hookenv.log.assert_any_call(
            "Forward result for unit_id: 0, "
            "ip: 10.0.0.99, exitcode: 0"
        )
        self.hookenv.log.assert_any_call(
            "Original IP and Forward MATCH OK for unit_id: 0, "
            "Original: 10.0.0.99, "
            "Forward: ['10.0.0.99']", "INFO"
        )

    @patch('subprocess.check_output')
    def test_check_dns_gracefully_handles_no_answer(self, mock_subprocess):
        ip = "10.0.0.99"
        unit_id = "magpie/0"
        self.hookenv.config.return_value = {
            "dns_server": "127.0.0.1",
            "dns_tries": "1",
            "dns_time": "3"
        }
        rev_response = """
        -
          type: MESSAGE
          message:
            response_message_data: {}
        """
        fwd_response = """
        -
          type: MESSAGE
          message:
            response_message_data: {}
        """
        mock_subprocess.side_effect = [
            bytes(rev_response, "utf-8"),  # for reverse_dns
            bytes(fwd_response, "utf-8")  # for forward_dns
        ]
        norev, nofwd, nomatch = magpie_tools.check_dns([(unit_id, ip)])
        self.assertEqual(
            norev, ['0'], "Reverse lookup had an answer for {}".format(ip))
        self.assertEqual(
            nofwd, [], ("Forward lookup failed for IP {}, "
                        "faked to example.com".format(ip)))
        self.assertEqual(
            nomatch, [], "Reverse and forward lookups didn't match")
