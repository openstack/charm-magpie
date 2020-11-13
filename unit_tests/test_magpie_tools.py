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
