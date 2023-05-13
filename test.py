#!/usr/bin/env python3

import unittest
import logging
import xmltodict
from kannel_exporter import KannelCollector, uptime_to_secs, bearerbox_version
from kannel_exporter import read_password_file, CollectorOpts

logging.basicConfig(level=logging.CRITICAL)


class KannelCollectorTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open('test/v150.xml') as xml:
            cls.status150 = xmltodict.parse(xml.read())

        with open('test/v145.xml') as xml:
            cls.status145 = xmltodict.parse(xml.read())

    def test_uptime_to_secs(self):
        uptime1 = uptime_to_secs("running, uptime 0d 1h 16m 31s")
        uptime2 = uptime_to_secs("running, uptime 0d 0h 1m 38s")
        uptime3 = uptime_to_secs("on-line 0d 0h 1m 53s")
        self.assertEqual(uptime1, 4591)
        self.assertEqual(uptime2, 98)
        self.assertEqual(uptime3, 113)

    def test_kannel_collector(self):
        exporter = KannelCollector('', '')
        self.assertEqual(exporter.parse_kannel_status(), None)

    def test_collector_opts(self):
        opts_def = CollectorOpts()
        opts_nondef = CollectorOpts(5, True, True, False, False, ['smsbox'])
        self.assertEqual(opts_def.timeout, 15)
        self.assertEqual(opts_def.filter_smsc, False)
        self.assertEqual(opts_def.collect_wdp, False)
        self.assertEqual(opts_def.collect_box_uptime, False)
        self.assertEqual(opts_def.box_connections, ['wapbox', 'smsbox'])
        self.assertEqual(opts_nondef.timeout, 5)
        self.assertEqual(opts_nondef.filter_smsc, True)
        self.assertEqual(opts_nondef.collect_wdp, True)
        self.assertEqual(opts_nondef.collect_box_uptime, False)
        self.assertEqual(opts_nondef.box_connections, ['smsbox'])

    def test_read_password(self):
        password = read_password_file('test/secret')
        self.assertEqual(password, 'supersecret')

    def test_bearerbox_version(self):
        version1 = """Kannel bearerbox version `1.4.5'.
Build `Jul  9 2018 21:06:42', compiler `4.8.5 20150623 (Red Hat 4.8.5-11)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64, version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.52-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc."""
        version2 = """Kannel bearerbox version 1.4.4'.
Build `Jun 13 2018 04:21:44', compiler `4.8.5 20150623 (Red Hat 4.8.5-28)'.
System Linux, release 3.10.0-693.11.6.el7.x86_64, version #1 SMP Thu Jan 4 01:06:37 UTC 2018, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.2k-fips 26 Jan 2017.
Using native malloc."""
        version3 = """Kannel bearerbox version `svn-r5150'.
Build `Sep 28 2015 02:39:14', compiler `4.8.3 20140911 (Red Hat 4.8.3-9)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64, version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.44-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc."""
        version4 = """Kannel-HA bearerbox version `svn-r5150'.
Build `Sep 28 2015 02:39:14', compiler `4.8.3 20140911 (Red Hat 4.8.3-9)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64, version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.44-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc."""
        self.assertEqual(bearerbox_version(version1), "1.4.5")
        self.assertEqual(bearerbox_version(version2), "1.4.4")
        self.assertEqual(bearerbox_version(version3), "svn-r5150")
        self.assertEqual(bearerbox_version(version4), "svn-r5150")
        self.assertEqual(bearerbox_version(""), "")

    def test_msg_metrics(self):
        exporter = KannelCollector('', '')
        metrics = exporter.collect_msg_stats(self.status150['gateway'])
        self.assertEqual(metrics[0].documentation, 'Total number of SMS received')
        self.assertEqual(metrics[0].samples[0].value, 10)
        self.assertEqual(metrics[1].documentation, 'Number of received SMS in queue')
        self.assertEqual(metrics[1].samples[0].value, 5)
        self.assertEqual(metrics[2].documentation, 'Total number of SMS sent')
        self.assertEqual(metrics[2].samples[0].value, 30)
        self.assertEqual(metrics[3].documentation, 'Number of sent SMS in queue')
        self.assertEqual(metrics[3].samples[0].value, 3)
        self.assertEqual(metrics[4].documentation, 'Number of SMS in storesize')
        self.assertEqual(metrics[4].samples[0].value, 0)
        self.assertEqual(metrics[5].documentation, 'Total number of DLR received')
        self.assertEqual(metrics[5].samples[0].value, 60)
        self.assertEqual(metrics[6].documentation, 'Total number of DLR sent')
        self.assertEqual(metrics[6].samples[0].value, 24)
        self.assertEqual(metrics[7].documentation, 'Number of DLRs in queue')
        self.assertEqual(metrics[7].samples[0].value, 14)
        self.assertEqual(metrics[8].documentation, 'DLR storage type info')
        self.assertEqual(metrics[8].samples[0].value, 1)
        self.assertEqual(metrics[8].samples[0].labels['storage'], 'mysql')

    def test_box_metrics(self):
        # bearerbox_box_connections Number of box connections
        opts = CollectorOpts(collect_box_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_box_stats(self.status150['gateway']['boxes'])
        self.assertEqual(metrics[0].documentation, 'Number of box connections')
        self.assertEqual(metrics[0].samples[0].value, 0)
        self.assertEqual(metrics[0].samples[0].labels['type'], 'wapbox')
        self.assertEqual(metrics[0].samples[1].value, 1)
        self.assertEqual(metrics[0].samples[1].labels['type'], 'smsbox')
        self.assertEqual(metrics[0].samples[2].value, 1)
        self.assertEqual(metrics[0].samples[2].labels['type'], 'sqlbox')
        self.assertEqual(metrics[1].documentation, 'Number of messages in box queue')
        self.assertEqual(metrics[1].samples[0].value, 7)
        self.assertEqual(metrics[1].samples[1].value, 10)
        self.assertEqual(metrics[2].documentation, 'Box uptime in seconds (*)')
        self.assertEqual(metrics[2].samples[0].value, 3780)
        self.assertEqual(metrics[2].samples[1].value, 3545)

    def check_smsc_metrics(self, metrics):
        self.assertEqual(metrics[0].documentation, 'Total number of SMSC failed messages')
        self.assertEqual(metrics[0].samples[0].value, 3)
        self.assertEqual(metrics[0].samples[1].value, 4)
        self.assertEqual(metrics[0].samples[2].value, 8)
        self.assertEqual(metrics[0].samples[3].value, 2)
        self.assertEqual(metrics[1].documentation, 'Number of SMSC queued messages')
        self.assertEqual(metrics[1].samples[0].value, 1)
        self.assertEqual(metrics[1].samples[1].value, 3)
        self.assertEqual(metrics[1].samples[2].value, 2)
        self.assertEqual(metrics[1].samples[3].value, 5)
        self.assertEqual(metrics[2].documentation, 'Total number of received SMS by SMSC')
        self.assertEqual(metrics[2].samples[0].value, 0)
        self.assertEqual(metrics[2].samples[1].value, 7)
        self.assertEqual(metrics[2].samples[2].value, 2)
        self.assertEqual(metrics[2].samples[3].value, 1)
        self.assertEqual(metrics[3].documentation, 'Total number of SMS sent to SMSC')
        self.assertEqual(metrics[3].samples[0].value, 15)
        self.assertEqual(metrics[3].samples[1].value, 10)
        self.assertEqual(metrics[3].samples[2].value, 3)
        self.assertEqual(metrics[3].samples[3].value, 2)
        self.assertEqual(metrics[4].documentation, 'Total number of DLRs received by SMSC')
        self.assertEqual(metrics[4].samples[0].value, 30)
        self.assertEqual(metrics[4].samples[1].value, 20)
        self.assertEqual(metrics[4].samples[2].value, 6)
        self.assertEqual(metrics[4].samples[3].value, 4)
        self.assertEqual(metrics[5].documentation, 'Total number of DLRs sent to SMSC')
        self.assertEqual(metrics[5].samples[0].value, 0)
        self.assertEqual(metrics[5].samples[1].value, 16)
        self.assertEqual(metrics[5].samples[2].value, 5)
        self.assertEqual(metrics[5].samples[3].value, 3)
        self.assertEqual(metrics[6].documentation, 'Number of online SMSC connections')
        self.assertEqual(metrics[6].samples[0].value, 1)
        self.assertEqual(metrics[6].samples[1].value, 1)
        self.assertEqual(metrics[6].samples[2].value, 0)
        self.assertEqual(metrics[6].samples[3].value, 0)
        self.assertEqual(metrics[7].documentation, 'Number of offline SMSC connections')
        self.assertEqual(metrics[7].samples[0].value, 0)
        self.assertEqual(metrics[7].samples[1].value, 0)
        self.assertEqual(metrics[7].samples[2].value, 1)
        self.assertEqual(metrics[7].samples[3].value, 2)
        self.assertEqual(metrics[8].documentation, 'SMSC uptime in seconds (*)')
        self.assertEqual(metrics[8].samples[0].value, 178)
        self.assertEqual(metrics[8].samples[1].value, 41)
        self.assertEqual(metrics[8].samples[2].value, 0)
        self.assertEqual(metrics[8].samples[3].value, 0)

    def test_smsc_metrics_v150(self):
        opts = CollectorOpts(collect_smsc_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_smsc_stats(self.status150['gateway']['smscs'])
        self.check_smsc_metrics(metrics)

    def test_smsc_metrics_v145(self):
        opts = CollectorOpts(collect_smsc_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_smsc_stats(self.status145['gateway']['smscs'])
        self.check_smsc_metrics(metrics)


if __name__ == "__main__":
    unittest.main()
