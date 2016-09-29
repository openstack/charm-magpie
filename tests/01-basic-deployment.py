#!/usr/bin/env python3

import unittest
import amulet


class TestDeploy(unittest.TestCase):
    """
    Trivial deployment test for Magpie to test ICMP and DNS
    """

    def test_deploy(self):
        self.d = amulet.Deployment(series='trusty')
        self.d.add('magpie', 'magpie', units=2)
        self.d.setup(timeout=900)
        self.d.sentry.wait(timeout=1800)
        self.unit = self.d.sentry['magpie'][0]


if __name__ == '__main__':
    unittest.main()
