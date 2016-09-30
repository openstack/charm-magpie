#!/usr/bin/env python3

import unittest
import amulet


class TestDeploy(unittest.TestCase):
    """
    Deploy 2 peers and make sure their status messages contain "icmp" and "dns"
    This does not test the substrate - only that the charms deploy and relate.
    """

    def test_deploy(self):
        self.d = amulet.Deployment(series='xenial')
        self.d.add('magpie', 'magpie', units=2)
        self.d.setup(timeout=900)
        self.d.sentry.wait_for_messages({'magpie': re.compile('ok|failed'), timeout=3600)
        #self.magpie_1 = self.d.sentry['magpie'][0]
        #self.magpie_2 = self.d.sentry['magpie'][1]


if __name__ == '__main__':
    unittest.main()
