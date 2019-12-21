#!/usr/bin/env python3

import unittest
import logging
import xmltodict
from kannel_exporter import KannelCollector, uptime_to_secs, bearerbox_version
from kannel_exporter import get_password, CollectorOpts

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
        opts_nondef = CollectorOpts(True, True, False, False, ['smsbox'])
        self.assertEqual(opts_def.filter_smsc, False)
        self.assertEqual(opts_def.collect_wdp, False)
        self.assertEqual(opts_def.collect_box_uptime, False)
        self.assertEqual(opts_def.box_connections, ['wapbox', 'smsbox'])
        self.assertEqual(opts_nondef.filter_smsc, True)
        self.assertEqual(opts_nondef.collect_wdp, True)
        self.assertEqual(opts_nondef.collect_box_uptime, False)
        self.assertEqual(opts_nondef.box_connections, ['smsbox'])

    def test_get_password(self):
        password = get_password('mypass', None)
        self.assertEqual(password, 'mypass')

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
        self.assertEqual(metrics['bearerbox_sms_received_total'].documentation,
                         'Total number of SMS received')
        self.assertEqual(metrics['bearerbox_sms_received_total'].samples[0].value, 10)
        self.assertEqual(metrics['bearerbox_sms_received_queued'].documentation,
                         'Number of received SMS in queue')
        self.assertEqual(metrics['bearerbox_sms_received_queued'].samples[0].value, 5)
        self.assertEqual(metrics['bearerbox_sms_sent_total'].documentation,
                         'Total number of SMS sent')
        self.assertEqual(metrics['bearerbox_sms_sent_total'].samples[0].value, 30)
        self.assertEqual(metrics['bearerbox_sms_sent_queued'].documentation,
                         'Number of sent SMS in queue')
        self.assertEqual(metrics['bearerbox_sms_sent_queued'].samples[0].value, 3)
        self.assertEqual(metrics['bearerbox_sms_storesize'].documentation,
                         'Number of SMS in storesize')
        self.assertEqual(metrics['bearerbox_sms_storesize'].samples[0].value, 0)
        self.assertEqual(metrics['bearerbox_dlr_received_total'].documentation,
                         'Total number of DLR received')
        self.assertEqual(metrics['bearerbox_dlr_received_total'].samples[0].value, 60)
        self.assertEqual(metrics['bearerbox_dlr_sent_total'].documentation,
                         'Total number of DLR sent')
        self.assertEqual(metrics['bearerbox_dlr_sent_total'].samples[0].value, 24)
        self.assertEqual(metrics['bearerbox_dlr_queued'].documentation,
                         'Number of DLRs in queue')
        self.assertEqual(metrics['bearerbox_dlr_queued'].samples[0].value, 14)
        self.assertEqual(metrics['bearerbox_dlr_storage'].documentation,
                         'DLR storage type info')
        self.assertEqual(metrics['bearerbox_dlr_storage'].samples[0].value, 1)
        self.assertEqual(metrics['bearerbox_dlr_storage'].samples[0].labels['storage'], 'mysql')

    def test_box_metrics(self):
        # bearerbox_box_connections Number of box connections
        opts = CollectorOpts(collect_box_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_box_stats(self.status150['gateway']['boxes'])
        self.assertEqual(metrics['box_connections'].documentation,
                         'Number of box connections')
        self.assertEqual(metrics['box_connections'].samples[0].value, 0)
        self.assertEqual(metrics['box_connections'].samples[0].labels['type'], 'wapbox')
        self.assertEqual(metrics['box_connections'].samples[1].value, 1)
        self.assertEqual(metrics['box_connections'].samples[1].labels['type'], 'smsbox')
        self.assertEqual(metrics['box_connections'].samples[2].value, 1)
        self.assertEqual(metrics['box_connections'].samples[2].labels['type'], 'sqlbox')
        self.assertEqual(metrics['box_uptime'].documentation, 'Box uptime in seconds (*)')
        self.assertEqual(metrics['box_uptime'].samples[0].value, 3780)
        self.assertEqual(metrics['box_uptime'].samples[1].value, 3545)
        self.assertEqual(metrics['box_queue'].documentation, 'Number of messages in box queue')
        self.assertEqual(metrics['box_queue'].samples[0].value, 7)
        self.assertEqual(metrics['box_queue'].samples[1].value, 10)

    def check_smsc_metrics(self, metrics):
        self.assertEqual(metrics['smsc_count'].documentation, 'Number of SMSC connections')
        self.assertEqual(metrics['smsc_count'].samples[0].value, 5)
        self.assertEqual(metrics['failed'].documentation,
                         'Total number of SMSC failed messages')
        self.assertEqual(metrics['failed'].samples[0].value, 3)
        self.assertEqual(metrics['failed'].samples[1].value, 4)
        self.assertEqual(metrics['failed'].samples[2].value, 8)
        self.assertEqual(metrics['failed'].samples[3].value, 2)
        self.assertEqual(metrics['queued'].documentation, 'Number of SMSC queued messages')
        self.assertEqual(metrics['queued'].samples[0].value, 1)
        self.assertEqual(metrics['queued'].samples[1].value, 3)
        self.assertEqual(metrics['queued'].samples[2].value, 2)
        self.assertEqual(metrics['queued'].samples[3].value, 5)
        self.assertEqual(metrics['uptime'].documentation,
                         'SMSC uptime in seconds (*)')
        self.assertEqual(metrics['uptime'].samples[0].value, 178)
        self.assertEqual(metrics['uptime'].samples[1].value, 41)
        self.assertEqual(metrics['uptime'].samples[2].value, 0)
        self.assertEqual(metrics['uptime'].samples[3].value, 0)
        self.assertEqual(metrics['sms_received'].documentation,
                         'Total number of received SMS by SMSC')
        self.assertEqual(metrics['sms_received'].samples[0].value, 0)
        self.assertEqual(metrics['sms_received'].samples[1].value, 7)
        self.assertEqual(metrics['sms_received'].samples[2].value, 2)
        self.assertEqual(metrics['sms_received'].samples[3].value, 1)
        self.assertEqual(metrics['sms_sent'].documentation,
                         'Total number of SMS sent to SMSC')
        self.assertEqual(metrics['sms_sent'].samples[0].value, 15)
        self.assertEqual(metrics['sms_sent'].samples[1].value, 10)
        self.assertEqual(metrics['sms_sent'].samples[2].value, 3)
        self.assertEqual(metrics['sms_sent'].samples[3].value, 2)
        self.assertEqual(metrics['dlr_received'].documentation,
                         'Total number of DLRs received by SMSC')
        self.assertEqual(metrics['dlr_received'].samples[0].value, 30)
        self.assertEqual(metrics['dlr_received'].samples[1].value, 20)
        self.assertEqual(metrics['dlr_received'].samples[2].value, 6)
        self.assertEqual(metrics['dlr_received'].samples[3].value, 4)
        self.assertEqual(metrics['dlr_sent'].documentation,
                         'Total number of DLRs sent to SMSC')
        self.assertEqual(metrics['dlr_sent'].samples[0].value, 0)
        self.assertEqual(metrics['dlr_sent'].samples[1].value, 16)
        self.assertEqual(metrics['dlr_sent'].samples[2].value, 5)
        self.assertEqual(metrics['dlr_sent'].samples[3].value, 3)

    def test_smsc_metrics_v150(self):
        opts = CollectorOpts(collect_smsc_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_smsc_stats(self.status150['gateway']['smscs']['count'],
                                              self.status150['gateway']['smscs']['smsc'])
        self.check_smsc_metrics(metrics)

    def test_smsc_metrics_v145(self):
        opts = CollectorOpts(collect_smsc_uptime=True)
        exporter = KannelCollector('', '', opts)
        metrics = exporter.collect_smsc_stats(self.status145['gateway']['smscs']['count'],
                                              self.status145['gateway']['smscs']['smsc'])
        self.check_smsc_metrics(metrics)


if __name__ == "__main__":
    unittest.main()
