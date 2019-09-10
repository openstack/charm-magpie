#!/usr/bin/env python3

import re
import unittest
import amulet


class TestDeploy(unittest.TestCase):
    """
    Deploy 2 peers and make sure their status messages contain "or" or "failed"
    This does not test the substrate - only that the charms deploy and relate.
    """

    @classmethod
    def setUpClass(cls):
        cls.d = amulet.Deployment(series='xenial')
        cls.d.add('magpie', charm='~admcleod/magpie', units=2)
        cls.d.setup(timeout=900)
        cls.magpie_0 = cls.d.sentry['magpie'][0]
        cls.magpie_1 = cls.d.sentry['magpie'][1]

    def test_deploy(self):
        self.d.sentry.wait_for_messages({'magpie': re.compile('ok|failed')},
                                        timeout=60)

    # following test is commented out until this bug is resolved;
    # https://bugs.launchpad.net/juju/+bug/1623480
    # def test_check_local_hostname(self):
    # self.d.sentry.wait_for_messages({'magpie': {re.compile('.*hostname
    #                                   ok.*'}}, timeout=60)

    def test_break_dns_single(self):
        print('Test break dns single...')
        """
        Break DNS on one unit, make sure DNS check fails, fix DNS, toggle
        back
        """
        self.d.sentry.wait_for_messages({'magpie': 'icmp ok, dns ok'},
                                        timeout=60)
        self.magpie_0.run("sudo mv /etc/resolv.conf /etc/resolv.conf.bak")
        self.magpie_0.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie':
                                        {re.compile('.*dns failed*')}},
                                        timeout=60)
        self.magpie_0.run("sudo mv /etc/resolv.conf.bak /etc/resolv.conf")
        self.magpie_0.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie': 'icmp ok, dns ok'},
                                        timeout=60)

    def test_break_dns_all(self):
        print('Test break dns all...')
        """
        Set DNS with action to 255.255.255.255 - All units should fail DNS.
        """
        self.d.configure('magpie', {'dns_server': '255.255.255.255'})
        self.magpie_0.run("hooks/update-status")
        self.magpie_1.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie':
                                         re.compile('icmp ok,.*dns failed.*')})
        self.d.configure('magpie', {'dns_server': ''})
        self.magpie_0.run("hooks/update-status")
        self.magpie_1.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie': 'icmp ok, dns ok'})

    def test_break_ping_single(self):
        print('Test break ping single')
        """
        Take primary interface down and make sure ICMP fails.
        """
        stoprestart = "(sudo service networking stop; sleep 60; service \
                        networking start) & "
        self.magpie_1.run(stoprestart)
        self.magpie_1.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie':
                                        {re.compile('icmp failed.*')}},
                                        timeout=120)
        self.magpie_1.run("hooks/update-status")
        self.d.sentry.wait_for_messages({'magpie': {re.compile('icmp ok.*')}},
                                        timeout=120)


if __name__ == '__main__':
    unittest.main()
