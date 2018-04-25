#!/usr/bin/env python3

import unittest
from kannel_exporter import KannelCollector, uptime_to_secs


class KannelCollectorTestCase(unittest.TestCase):

    def test_uptime_to_secs(self):
        uptime1 = uptime_to_secs("running, uptime 0d 1h 16m 31s")
        uptime2 = uptime_to_secs("running, uptime 0d 0h 1m 38s")
        uptime3 = uptime_to_secs("on-line 0d 0h 1m 53s")
        self.assertEqual(uptime1, 4591)
        self.assertEqual(uptime2, 98)
        self.assertEqual(uptime3, 113)

    def test_kannel_collector(self):
        exporter = KannelCollector('', '', False)
        self.assertEqual(exporter.parse_kannel_status(), None)


if __name__ == "__main__":
    unittest.main()
