#!/usr/bin/env python3

import logging
import unittest
from functools import cache
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from parameterized.parameterized import parameterized

from kannel_exporter import (
    CollectorOpts,
    KannelCollector,
    bearerbox_version,
    read_password_file,
    uptime_to_secs,
)

logging.basicConfig(level=logging.CRITICAL)


@cache
def get_kannel_status(xml_path: str) -> dict[str, Any]:
    with open(xml_path, 'rb') as f:
        xml_bytes = f.read()
    with patch('kannel_exporter.urlopen') as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = xml_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_response
        status = KannelCollector('http://localhost', 'secret').parse_kannel_status()
        assert status is not None
        return status


class KannelCollectorTestCase(unittest.TestCase):

    @parameterized.expand([
        ("running, uptime 0d 1h 16m 31s", 4591),
        ("running, uptime 0d 0h 1m 38s", 98),
        ("on-line 0d 0h 1m 53s", 113),
    ])
    def test_uptime_to_secs(self, uptime_str, expected):
        self.assertEqual(uptime_to_secs(uptime_str), expected)

    @parameterized.expand([
        (
            "denied_auth",
            b"<gateway>Denied</gateway>",
            None,
            "Authentication failed."
        ),
        (
            "invalid_xml",
            b"<gateway><invalid>",
            None,
            "Failed to parse status XML"
        ),
        (
            "network_timeout",
            None,
            URLError("timed out"),
            "Failed to open target URL"
        ),
        (
            "unknown_url_type",
            None,
            ValueError("unknown url type"),
            "Uknown URL type"
        ),
    ])
    def test_parse_kannel_status_errors(self, _name, response_data, side_effect, expected_log):
        with patch('kannel_exporter.urlopen') as mock_urlopen:
            if side_effect:
                mock_urlopen.side_effect = side_effect
            else:
                mock_response = MagicMock()
                mock_response.read.return_value = response_data
                mock_urlopen.return_value.__enter__.return_value = mock_response

            collector = KannelCollector('http://localhost:13000', 'secret')
            with self.assertLogs('kannel_exporter', level='ERROR') as log:
                result = collector.parse_kannel_status()

            self.assertIsNone(result)
            self.assertTrue(any(expected_log in message for message in log.output))

    @parameterized.expand([
        (
            "default",
            CollectorOpts(),
            {
                "timeout": 15,
                "disable_smsc": False,
                "collect_wdp": False,
                "collect_box_uptime": False,
                "collect_smsc_uptime": False,
                "box_connections": ["wapbox", "smsbox"]
            }
        ),
        (
            "non_default",
            CollectorOpts(5, True, True, False, False, ["smsbox"]),
            {
                "timeout": 5,
                "disable_smsc": True,
                "collect_wdp": True,
                "collect_box_uptime": False,
                "collect_smsc_uptime": False,
                "box_connections": ["smsbox"]
            }
        ),
    ])
    def test_collector_opts(self, _name, opts, expected_attrs):
        self.assertEqual(opts._asdict(), expected_attrs)

    def test_read_password(self):
        password = read_password_file('test/secret')
        self.assertEqual(password, 'supersecret')

    @parameterized.expand([
        (
            """Kannel bearerbox version `1.4.5'.
Build `Jul  9 2018 21:06:42', compiler `4.8.5 20150623 (Red Hat 4.8.5-11)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64,
version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.52-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc.""",
            "1.4.5"
        ),
        (
            """Kannel bearerbox version 1.4.4'.
Build `Jun 13 2018 04:21:44', compiler `4.8.5 20150623 (Red Hat 4.8.5-28)'.
System Linux, release 3.10.0-693.11.6.el7.x86_64,
version #1 SMP Thu Jan 4 01:06:37 UTC 2018, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.2k-fips 26 Jan 2017.
Using native malloc.""",
            "1.4.4"
        ),
        (
            """Kannel bearerbox version `svn-r5150'.
Build `Sep 28 2015 02:39:14', compiler `4.8.3 20140911 (Red Hat 4.8.3-9)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64,
version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.44-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc.""",
            "svn-r5150"
        ),
        (
            """Kannel-HA bearerbox version `svn-r5150'.
Build `Sep 28 2015 02:39:14', compiler `4.8.3 20140911 (Red Hat 4.8.3-9)'.
System Linux, release 3.10.0-514.21.1.el7.x86_64,
version #1 SMP Thu May 25 17:04:51 UTC 2017, machine x86_64.
Libxml version 2.9.1.
Using OpenSSL 1.0.1e-fips 11 Feb 2013.
Compiled with MySQL 5.5.44-MariaDB, using MySQL 5.5.52-MariaDB.
Using native malloc.""",
            "svn-r5150"
        ),
        ("", "")
    ])
    def test_bearerbox_version(self, version_str, expected):
        self.assertEqual(bearerbox_version(version_str), expected)

    @parameterized.expand([
        (
            "v150_default",
            "test/v150.xml",
            CollectorOpts(),
            [
                ("bearerbox_sms_received", "Total number of SMS received", [(10, {})]),
                ("bearerbox_sms_received_queued", "Number of received SMS in queue", [(5, {})]),
                ("bearerbox_sms_sent", "Total number of SMS sent", [(30, {})]),
                ("bearerbox_sms_sent_queued", "Number of sent SMS in queue", [(3, {})]),
                ("bearerbox_sms_storesize", "Number of SMS in storesize", [(0, {})]),
                ("bearerbox_dlr_received", "Total number of DLR received", [(60, {})]),
                ("bearerbox_dlr_sent", "Total number of DLR sent", [(24, {})]),
                ("bearerbox_dlr_queued", "Number of DLRs in queue", [(14, {})]),
                ("bearerbox_dlr_storage", "DLR storage type info", [(1, {'storage': 'mysql'})]),
            ]
        ),
        (
            "v145_default",
            "test/v145.xml",
            CollectorOpts(),
            [
                ("bearerbox_sms_received", "Total number of SMS received", [(10, {})]),
                ("bearerbox_sms_received_queued", "Number of received SMS in queue", [(5, {})]),
                ("bearerbox_sms_sent", "Total number of SMS sent", [(30, {})]),
                ("bearerbox_sms_sent_queued", "Number of sent SMS in queue", [(3, {})]),
                ("bearerbox_sms_storesize", "Number of SMS in storesize", [(0, {})]),
                ("bearerbox_dlr_received", "Total number of DLR received", [(60, {})]),
                ("bearerbox_dlr_sent", "Total number of DLR sent", [(24, {})]),
                ("bearerbox_dlr_queued", "Number of DLRs in queue", [(14, {})]),
                ("bearerbox_dlr_storage", "DLR storage type info", [(1, {'storage': 'mysql'})]),
            ]
        ),
        (
            "v150_with_wdp",
            "test/v150.xml",
            CollectorOpts(collect_wdp=True),
            [
                ("bearerbox_wdp_received", "Total number of WDP received", [(0, {})]),
                ("bearerbox_wdp_received_queued", "Number of received WDP in queue", [(0, {})]),
                ("bearerbox_wdp_sent", "Total number of WDP sent", [(0, {})]),
                ("bearerbox_wdp_sent_queued", "Number of sent WDP in queue", [(0, {})]),
                ("bearerbox_sms_received", "Total number of SMS received", [(10, {})]),
                ("bearerbox_sms_received_queued", "Number of received SMS in queue", [(5, {})]),
                ("bearerbox_sms_sent", "Total number of SMS sent", [(30, {})]),
                ("bearerbox_sms_sent_queued", "Number of sent SMS in queue", [(3, {})]),
                ("bearerbox_sms_storesize", "Number of SMS in storesize", [(0, {})]),
                ("bearerbox_dlr_received", "Total number of DLR received", [(60, {})]),
                ("bearerbox_dlr_sent", "Total number of DLR sent", [(24, {})]),
                ("bearerbox_dlr_queued", "Number of DLRs in queue", [(14, {})]),
                ("bearerbox_dlr_storage", "DLR storage type info", [(1, {'storage': 'mysql'})]),
            ]
        ),
        (
            "v145_with_wdp",
            "test/v145.xml",
            CollectorOpts(collect_wdp=True),
            [
                ("bearerbox_wdp_received", "Total number of WDP received", [(0, {})]),
                ("bearerbox_wdp_received_queued", "Number of received WDP in queue", [(0, {})]),
                ("bearerbox_wdp_sent", "Total number of WDP sent", [(0, {})]),
                ("bearerbox_wdp_sent_queued", "Number of sent WDP in queue", [(0, {})]),
                ("bearerbox_sms_received", "Total number of SMS received", [(10, {})]),
                ("bearerbox_sms_received_queued", "Number of received SMS in queue", [(5, {})]),
                ("bearerbox_sms_sent", "Total number of SMS sent", [(30, {})]),
                ("bearerbox_sms_sent_queued", "Number of sent SMS in queue", [(3, {})]),
                ("bearerbox_sms_storesize", "Number of SMS in storesize", [(0, {})]),
                ("bearerbox_dlr_received", "Total number of DLR received", [(60, {})]),
                ("bearerbox_dlr_sent", "Total number of DLR sent", [(24, {})]),
                ("bearerbox_dlr_queued", "Number of DLRs in queue", [(14, {})]),
                ("bearerbox_dlr_storage", "DLR storage type info", [(1, {'storage': 'mysql'})]),
            ]
        ),
    ])
    def test_msg_metrics(self, _name: str, xml_path: str, opts: CollectorOpts, expected):
        status = get_kannel_status(xml_path)
        metrics = KannelCollector('', '', opts).collect_msg_stats(status['gateway'])
        self.assertListEqual(
            [(m.name, m.documentation, [(s.value, s.labels) for s in m.samples]) for m in metrics],
            expected
        )

    @parameterized.expand([
        (
            "v150_with_uptime",
            "test/v150.xml",
            CollectorOpts(collect_box_uptime=True),
            [
                (
                    "bearerbox_box_connections",
                    "Number of box connections",
                    [
                        (0, {"type": "wapbox"}),
                        (1, {"type": "smsbox"}),
                        (1, {"type": "sqlbox"}),
                    ]
                ),
                (
                    "bearerbox_box_queue",
                    "Number of messages in box queue",
                    [
                        (7, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (10, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
                (
                    "bearerbox_box_uptime_seconds",
                    "Box uptime in seconds (*)",
                    [
                        (3780, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (3545, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
            ]
        ),
        (
            "v145_with_uptime",
            "test/v145.xml",
            CollectorOpts(collect_box_uptime=True),
            [
                (
                    "bearerbox_box_connections",
                    "Number of box connections",
                    [
                        (0, {"type": "wapbox"}),
                        (1, {"type": "smsbox"}),
                        (1, {"type": "sqlbox"}),
                    ]
                ),
                (
                    "bearerbox_box_queue",
                    "Number of messages in box queue",
                    [
                        (7, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (10, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
                (
                    "bearerbox_box_uptime_seconds",
                    "Box uptime in seconds (*)",
                    [
                        (3780, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (3545, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
            ]
        ),
        (
            "v150_default",
            "test/v150.xml",
            CollectorOpts(),
            [
                (
                    "bearerbox_box_connections",
                    "Number of box connections",
                    [
                        (0, {"type": "wapbox"}),
                        (1, {"type": "smsbox"}),
                        (1, {"type": "sqlbox"}),
                    ]
                ),
                (
                    "bearerbox_box_queue",
                    "Number of messages in box queue",
                    [
                        (7, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (10, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
            ]
        ),
        (
            "v145_default",
            "test/v145.xml",
            CollectorOpts(),
            [
                (
                    "bearerbox_box_connections",
                    "Number of box connections",
                    [
                        (0, {"type": "wapbox"}),
                        (1, {"type": "smsbox"}),
                        (1, {"type": "sqlbox"}),
                    ]
                ),
                (
                    "bearerbox_box_queue",
                    "Number of messages in box queue",
                    [
                        (7, {"type": "smsbox", "id": "smsbox", "ipaddr": "127.0.0.1"}),
                        (10, {"type": "sqlbox", "id": "sqlbox", "ipaddr": "127.0.0.1"}),
                    ]
                ),
            ]
        ),
    ])
    def test_box_metrics(self, _name, xml_path, opts, expected):
        status = get_kannel_status(xml_path)
        metrics = KannelCollector('', '', opts).collect_box_stats(status['gateway']['boxes'])
        self.assertListEqual(
            [(m.name, m.documentation, [(s.value, s.labels) for s in m.samples]) for m in metrics],
            expected
        )

    @parameterized.expand([
        ("v150", "test/v150.xml"),
        ("v145", "test/v145.xml"),
    ])
    def test_smsc_metrics(self, _name, xml_path):
        opts = CollectorOpts(collect_smsc_uptime=True)
        status = get_kannel_status(xml_path)
        metrics = KannelCollector('', '', opts).collect_smsc_stats(status['gateway']['smscs'])
        expected = [
            (
                "bearerbox_smsc_failed_messages",
                "Total number of SMSC failed messages",
                [
                    (3, {"smsc_id": "fakesmsc"}),
                    (4, {"smsc_id": "httpsmsc"}),
                    (8, {"smsc_id": "smpp1"}),
                    (2, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_queued_messages",
                "Number of SMSC queued messages",
                [
                    (1, {"smsc_id": "fakesmsc"}),
                    (3, {"smsc_id": "httpsmsc"}),
                    (2, {"smsc_id": "smpp1"}),
                    (5, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_received_sms",
                "Total number of received SMS by SMSC",
                [
                    (0, {"smsc_id": "fakesmsc"}),
                    (7, {"smsc_id": "httpsmsc"}),
                    (2, {"smsc_id": "smpp1"}),
                    (1, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_sent_sms",
                "Total number of SMS sent to SMSC",
                [
                    (15, {"smsc_id": "fakesmsc"}),
                    (10, {"smsc_id": "httpsmsc"}),
                    (3, {"smsc_id": "smpp1"}),
                    (2, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_received_dlr",
                "Total number of DLRs received by SMSC",
                [
                    (30, {"smsc_id": "fakesmsc"}),
                    (20, {"smsc_id": "httpsmsc"}),
                    (6, {"smsc_id": "smpp1"}),
                    (4, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_sent_dlr",
                "Total number of DLRs sent to SMSC",
                [
                    (0, {"smsc_id": "fakesmsc"}),
                    (16, {"smsc_id": "httpsmsc"}),
                    (5, {"smsc_id": "smpp1"}),
                    (3, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_online_connections",
                "Number of online SMSC connections",
                [
                    (1, {"smsc_id": "fakesmsc"}),
                    (1, {"smsc_id": "httpsmsc"}),
                    (0, {"smsc_id": "smpp1"}),
                    (0, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_offline_connections",
                "Number of offline SMSC connections",
                [
                    (0, {"smsc_id": "fakesmsc"}),
                    (0, {"smsc_id": "httpsmsc"}),
                    (1, {"smsc_id": "smpp1"}),
                    (2, {"smsc_id": "smpp2"}),
                ],
            ),
            (
                "bearerbox_smsc_uptime_seconds",
                "SMSC uptime in seconds (*)",
                [
                    (178, {"smsc_id": "fakesmsc"}),
                    (41, {"smsc_id": "httpsmsc"}),
                    (0, {"smsc_id": "smpp1"}),
                    (0, {"smsc_id": "smpp2"}),
                ],
            ),
        ]
        self.assertListEqual(
            [(m.name, m.documentation, [(s.value, s.labels) for s in m.samples]) for m in metrics],
            expected
        )


if __name__ == "__main__":
    unittest.main()
