#!/usr/bin/env python3

import unittest
from kannel_exporter import KannelCollector, uptime_to_secs, bearerbox_version
from kannel_exporter import get_password


class KannelCollectorTestCase(unittest.TestCase):

    def test_uptime_to_secs(self):
        uptime1 = uptime_to_secs("running, uptime 0d 1h 16m 31s")
        uptime2 = uptime_to_secs("running, uptime 0d 0h 1m 38s")
        uptime3 = uptime_to_secs("on-line 0d 0h 1m 53s")
        self.assertEqual(uptime1, 4591)
        self.assertEqual(uptime2, 98)
        self.assertEqual(uptime3, 113)

    def test_kannel_collector(self):
        exporter = KannelCollector('', '', False, False)
        self.assertEqual(exporter.parse_kannel_status(), None)

    def test_get_password(self):
        password = get_password('mypass', None)
        self.assertEqual(password, 'mypass')

    def test_bearerbox_version(self):
        v1 = """Kannel bearerbox version `1.4.5'.
Build `Jul  9 2018 21:06:42', compiler `4.8.5 20150623 (Red Hat 4.8.5-11)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64, version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Hostname test.example.com, IP 10.0.0.1.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.52-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc."""
        v2 = """Kannel bearerbox version 1.4.4'.
Build `Jun 13 2018 04:21:44', compiler `4.8.5 20150623 (Red Hat 4.8.5-28)'.
System Linux, release 3.10.0-693.11.6.el7.x86_64, version #1 SMP Thu Jan 4 01:06:37 UTC 2018, machine x86_64.
Hostname test.example.com, IP 10.0.0.1.
Libxml version 2.9.1.
Using OpenSSL 1.0.2k-fips 26 Jan 2017.
Using native malloc."""
        v3 = """Kannel bearerbox version `svn-r5150'.
Build `Sep 28 2015 02:39:14', compiler `4.8.3 20140911 (Red Hat 4.8.3-9)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64, version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Hostname c7.home.lan, IP 10.0.0.101.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.44-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc."""
        self.assertEqual(bearerbox_version(v1), "1.4.5")
        self.assertEqual(bearerbox_version(v2), "1.4.4")
        self.assertEqual(bearerbox_version(v3), "svn-r5150")
        self.assertEqual(bearerbox_version(""), "")


if __name__ == "__main__":
    unittest.main()
