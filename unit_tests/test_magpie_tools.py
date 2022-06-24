import lib.charms.layer.magpie_tools as magpie_tools
import unit_tests.test_utils


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
