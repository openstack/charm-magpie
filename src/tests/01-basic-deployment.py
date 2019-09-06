#!/usr/bin/env python3

import unittest
import amulet


class TestDeploy(unittest.TestCase):
    """
    Trivial deployment test for Magpie
    """

    def test_deploy(self):
        self.d = amulet.Deployment(series='xenial')
        self.d.add('magpie', charm='~admcleod/magpie')
        self.d.setup(timeout=900)
        self.d.sentry.wait_for_messages({'magpie': 'Waiting for peers...'},
                                        timeout=3600)


if __name__ == '__main__':
    unittest.main()
