#!/usr/bin/env python3

"""Prometheus custom collector for Kannel gateway
https://github.com/apostvav/kannel_exporter"""

__version__ = '0.8.0'

import argparse
import logging
import os
import sys
import re
from urllib.request import urlopen
from urllib.error import URLError
from time import time
from collections import namedtuple
from wsgiref.simple_server import make_server
from typing import Any, Optional, Dict, List
from xml.parsers import expat
import xmltodict
from prometheus_client.registry import Collector
from prometheus_client.core import Metric
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import REGISTRY, PLATFORM_COLLECTOR
from prometheus_client import GC_COLLECTOR, PROCESS_COLLECTOR
from prometheus_client import make_wsgi_app

# logger
logger = logging.getLogger('kannel_exporter')  # pylint: disable=invalid-name


def uptime_to_secs(uptime: str) -> int:
    days, hours, mins, secs = re.findall(r'\d+', uptime)
    days = int(days) * 86400
    hours = int(hours) * 3600
    mins = int(mins) * 60
    secs = int(secs)
    return days + hours + mins + secs


def bearerbox_version(version: str) -> str:
    try:
        version = version.split('\n')[0]
        version_position = version.find('version ')
        # 'version ' is 8 chars long
        if version_position != -1:
            version = version[version_position + 8:].strip('`').rstrip('\'.')
        else:
            logger.warning(('Bearerbox version could not be found. '
                            'Version value set to empty string.'))
            version = ""
    except IndexError:
        logger.error(('Failed to parse gateway version. '
                      'Version value set to empty string.'))
        version = ""
    return version


def _xmlpostproc(path, key, value):  # pylint: disable=unused-argument
    if value is None:
        value = ""
    return key, value


CollectorOpts = namedtuple('CollectorOpts', ['timeout',
                                             'disable_smsc',
                                             'collect_wdp',
                                             'collect_box_uptime',
                                             'collect_smsc_uptime',
                                             'box_connections'])
CollectorOpts.__new__.__defaults__ = (15, False, False, False, False,
                                      ['wapbox', 'smsbox'])


class KannelCollector(Collector):
    def __init__(self, target, password, opts=CollectorOpts()):
        self.target = target
        self.password = password
        self.opts = opts

    def parse_kannel_status(self) -> Optional[Dict[str, Any]]:
        url = self.target + '/status.xml?password=' + self.password
        status = None
        xml = None

        try:
            with urlopen(url, timeout=self.opts.timeout) as response:
                xml = response.read()
            if xml is not None:
                status = xmltodict.parse(xml, postprocessor=_xmlpostproc)

                if status['gateway'] == 'Denied':
                    logger.error('Authentication failed.')
                    return None

        except ValueError as err:
            logger.error("Uknown URL type: %s. Error: %s", self.target, err)
        except URLError as err:
            logger.error("Failed to open target URL: %s. Error: %s", self.target, err)
        except expat.ExpatError as err:
            logger.error("Failed to parse status XML. Error: %s", err)

        return status

    def collect_msg_stats(self, gw_metrics: Dict[str, Any]) -> List[Metric]:
        metrics = []
        directions = ['received', 'sent']
        states = ['total', 'queued']

        # collect WDP metrics
        if self.opts.collect_wdp:
            for direction in directions:
                for state in states:
                    metric_name = f"bearerbox_wdp_{direction}_{state}"
                    if state == 'total':
                        metric_help = f"Total number of WDP {direction}"
                        metric = CounterMetricFamily(metric_name, metric_help)
                    else:
                        metric_help = f"Number of {direction} WDP in queue"
                        metric = GaugeMetricFamily(metric_name, metric_help)
                    metric_value = int(gw_metrics['wdp'][direction][state])
                    metric.add_sample(metric_name, value=metric_value,
                                      labels={})
                    metrics.append(metric)

        # collect SMS metrics
        for direction in directions:
            for state in states:
                metric_name = f"bearerbox_sms_{direction}_{state}"
                if state == 'total':
                    metric_help = f"Total number of SMS {direction}"
                    metric = CounterMetricFamily(metric_name, metric_help)
                else:
                    metric_help = f"Number of {direction} SMS in queue"
                    metric = GaugeMetricFamily(metric_name, metric_help)
                metric_value = int(gw_metrics['sms'][direction][state])
                metric.add_sample(metric_name, value=metric_value, labels={})
                metrics.append(metric)

        metric_name = 'bearerbox_sms_storesize'
        metric_value = int(gw_metrics['sms']['storesize'])
        metric = GaugeMetricFamily(metric_name, 'Number of SMS in storesize')
        metric.add_sample('bearerbox_sms_storesize', value=metric_value, labels={})
        metrics.append(metric)

        # collect DLR metrics
        for direction in directions:
            metric_name = f"bearerbox_dlr_{direction}_total"
            metric_help = f"Total number of DLR {direction}"
            metric_value = int(gw_metrics['dlr'][direction]['total'])
            metric = CounterMetricFamily(metric_name, metric_help)
            metric.add_sample(metric_name, value=metric_value, labels={})
            metrics.append(metric)

        metric_name = 'bearerbox_dlr_queued'
        metric_value = int(gw_metrics['dlr']['queued'])
        metric = GaugeMetricFamily(metric_name, "Number of DLRs in queue")
        metric.add_sample(metric_name, value=metric_value, labels={})
        metrics.append(metric)

        metric_name = 'bearerbox_dlr_storage'
        metric = GaugeMetricFamily(metric_name, 'DLR storage type info')
        metric_labels = {'storage': gw_metrics['dlr']['storage']}
        metric.add_sample(metric_name, value=1, labels=metric_labels)
        metrics.append(metric)

        return metrics

    @staticmethod
    def _collect_box_uptime(box_details, box, tuplkey):
        # Helper method to collect box uptime metrics.
        # In case of multiple boxes with same type, id and host,
        # only the lowest uptime value will be exposed in order to avoid duplicates.
        uptime = uptime_to_secs(box['status'])

        if tuplkey in box_details:
            if ('uptime' not in box_details[tuplkey] or
                    uptime < box_details[tuplkey]['uptime']):
                box_details[tuplkey]['uptime'] = uptime
        else:
            box_details[tuplkey] = {}
            box_details[tuplkey]['uptime'] = uptime_to_secs(box['status'])

    def collect_box_stats(self, box_metrics: Dict[str, Any]) -> List[Metric]:
        metrics = []
        box_connections = {b: 0 for b in self.opts.box_connections}
        box_details = {}

        box_conn_mtr = GaugeMetricFamily('bearerbox_box_connections',
                                         'Number of box connections')
        box_queue_mtr = GaugeMetricFamily('bearerbox_box_queue',
                                          'Number of messages in box queue')
        box_uptime_mtr = GaugeMetricFamily('bearerbox_box_uptime_seconds',
                                           'Box uptime in seconds (*)')

        if box_metrics:
            # when there's only one box connected on the gateway
            # xmltodict returns an OrderedDict instead of a list of OrderedDicts
            if not isinstance(box_metrics['box'], list):
                box_metrics['box'] = [box_metrics['box']]

            for box in box_metrics['box']:
                box_connections[box['type']] = box_connections.get(box['type'], 0) + 1

                # some type of boxes (e.g wapbox) don't have IDs.
                box['id'] = box.get('id', '')

                tuplkey = (box['type'], box['id'], box['IP'])

                # some type of boxes (e.g wapbox) don't have queues.
                if 'queue' in box:
                    if tuplkey not in box_details:
                        box_details[tuplkey] = {}
                    box_details[tuplkey]['queue'] = (box_details[tuplkey].get('queue', 0)
                                                     + int(box['queue']))

                # collect box uptime metrics
                if self.opts.collect_box_uptime is True:
                    self._collect_box_uptime(box_details, box, tuplkey)

        for key, value in box_connections.items():
            box_conn_mtr.add_sample('bearerbox_box_connections',
                                     value=value, labels={'type': key})

        metrics.append(box_conn_mtr)

        for key, value in box_details.items():
            box_labels = {'type': key[0], 'id': key[1], 'ipaddr': key[2]}
            if 'queue' in value:
                box_queue_mtr.add_sample('bearerbox_box_queue',
                                         value=value['queue'],
                                         labels=box_labels)
            if self.opts.collect_box_uptime is True:
                box_uptime_mtr.add_sample('bearerbox_box_uptime_seconds',
                                          value=value['uptime'],
                                          labels=box_labels)

        metrics.append(box_queue_mtr)

        if self.opts.collect_box_uptime is True:
            metrics.append(box_uptime_mtr)

        return metrics

    def _aggregate_smsc_stats(self, smsc_metrics:List[Dict]) -> Dict[str, Any]:
        aggreg = {}

        for smsc in smsc_metrics:
            smscid = smsc['id']

            if smscid not in aggreg:
                aggreg[smscid] = {}
                aggreg[smscid]['sms'] = {}
                aggreg[smscid]['dlr'] = {}
                aggreg[smscid]['online'] = 0
                aggreg[smscid]['offline'] = 0

            aggreg[smscid]['failed'] = (aggreg[smscid].get('failed', 0)
                                        + int(smsc['failed']))
            aggreg[smscid]['queued'] = (aggreg[smscid].get('queued', 0)
                                        + int(smsc['queued']))

            smsc_status = re.findall(r'\d+', smsc['status'])

            if smsc_status:
                aggreg[smscid]['online'] += 1
                if self.opts.collect_smsc_uptime is True:
                    aggreg[smscid]['uptime'] = int(smsc_status[0])
            else:
                aggreg[smscid]['offline'] += 1
                if self.opts.collect_smsc_uptime is True:
                    aggreg[smscid]['uptime'] = 0

            # kannel 1.5 exposes metrics in a different format
            if 'sms' not in smsc:
                aggreg[smscid]['sms']['received'] = (aggreg[smscid]['sms'].get('received', 0)
                                                     + int(smsc['received']['sms']))
                aggreg[smscid]['sms']['sent'] = (aggreg[smscid]['sms'].get('sent', 0)
                                                 + int(smsc['sent']['sms']))
                aggreg[smscid]['dlr']['received'] = (aggreg[smscid]['dlr'].get('received', 0)
                                                     + int(smsc['received']['dlr']))
                aggreg[smscid]['dlr']['sent'] = (aggreg[smscid]['dlr'].get('sent', 0)
                                                 + int(smsc['sent']['dlr']))
            else:
                aggreg[smscid]['sms']['received'] = (aggreg[smscid]['sms'].get('received', 0)
                                                     + int(smsc['sms']['received']))
                aggreg[smscid]['sms']['sent'] = (aggreg[smscid]['sms'].get('sent', 0)
                                                 + int(smsc['sms']['sent']))
                aggreg[smscid]['dlr']['received'] = (aggreg[smscid]['dlr'].get('received', 0)
                                                     + int(smsc['dlr']['received']))
                aggreg[smscid]['dlr']['sent'] = (aggreg[smscid]['dlr'].get('sent', 0)
                                                 + int(smsc['dlr']['sent']))

        return aggreg

    def collect_smsc_stats(self, smsc_metrics: Dict[str, Any]) -> List[Metric]:
        failed = CounterMetricFamily('bearerbox_smsc_failed_messages_total',
                                     'Total number of SMSC failed messages',
                                     labels=['smsc_id'])
        queued = GaugeMetricFamily('bearerbox_smsc_queued_messages',
                                   'Number of SMSC queued messages',
                                   labels=['smsc_id'])
        sms_received = CounterMetricFamily('bearerbox_smsc_received_sms_total',
                                           'Total number of received SMS by SMSC',
                                           labels=['smsc_id'])
        sms_sent = CounterMetricFamily('bearerbox_smsc_sent_sms_total',
                                       'Total number of SMS sent to SMSC',
                                       labels=['smsc_id'])
        dlr_received = CounterMetricFamily('bearerbox_smsc_received_dlr_total',
                                           'Total number of DLRs received by SMSC',
                                           labels=['smsc_id'])
        dlr_sent = CounterMetricFamily('bearerbox_smsc_sent_dlr_total',
                                       'Total number of DLRs sent to SMSC',
                                       labels=['smsc_id'])
        conn_online = GaugeMetricFamily('bearerbox_smsc_online_connections',
                                        'Number of online SMSC connections',
                                        labels=['smsc_id'])
        conn_offline = GaugeMetricFamily('bearerbox_smsc_offline_connections',
                                         'Number of offline SMSC connections',
                                         labels=['smsc_id'])
        uptime = GaugeMetricFamily('bearerbox_smsc_uptime_seconds',
                                   'SMSC uptime in seconds (*)',
                                   labels=['smsc_id'])

        # when there's only one smsc connection on the gateway
        # xmltodict returns a dict instead of a list of dicts
        if not isinstance(smsc_metrics['smsc'], list):
            smsc_metrics['smsc'] = [smsc_metrics['smsc']]

        # Aggregate SMSC metrics by smsc-id
        aggreg = self._aggregate_smsc_stats(smsc_metrics['smsc'])

        for smsc in aggreg:  # pylint: disable=consider-using-dict-items
            failed.add_metric([smsc], aggreg[smsc]['failed'])
            queued.add_metric([smsc], aggreg[smsc]['queued'])
            sms_received.add_metric([smsc], aggreg[smsc]['sms']['received'])
            sms_sent.add_metric([smsc], aggreg[smsc]['sms']['sent'])
            dlr_received.add_metric([smsc], aggreg[smsc]['dlr']['received'])
            dlr_sent.add_metric([smsc], aggreg[smsc]['dlr']['sent'])
            conn_online.add_metric([smsc], aggreg[smsc]['online'])
            conn_offline.add_metric([smsc], aggreg[smsc]['offline'])

            if self.opts.collect_smsc_uptime is True:
                uptime.add_metric([smsc], aggreg[smsc]['uptime'])

        metrics = [
            failed,
            queued,
            sms_received,
            sms_sent,
            dlr_received,
            dlr_sent,
            conn_online,
            conn_offline,
        ]

        if self.opts.collect_smsc_uptime:
            metrics.append(uptime)

        return metrics

    def collect(self):  # pylint: disable=inconsistent-return-statements
        # bearerbox server status
        metric = GaugeMetricFamily('bearerbox_up',
                                   'Could the bearerbox server be reached')

        start = time()

        response = self.parse_kannel_status()

        if response is None:
            metric.add_sample('bearerbox_up', value=0, labels={})
            yield metric
            return []

        metric.add_sample('bearerbox_up', value=1, labels={})
        yield metric

        # Version info
        version = bearerbox_version(response['gateway']['version'])
        metric = GaugeMetricFamily('bearerbox_build_info',
                                   'Kannel bearerbox version info')
        metric.add_sample('bearerbox_build_info', value=1,
                          labels={'version': version})
        yield metric

        # Gauge for the bearerbox uptime, in seconds
        uptime = uptime_to_secs(response['gateway']['status'])
        metric = GaugeMetricFamily('bearerbox_uptime_seconds',
                                   'Current uptime in seconds (*)')
        metric.add_sample('bearerbox_uptime_seconds', value=uptime, labels={})
        yield metric

        # WDP, SMS & DLR metrics
        msg_metrics = self.collect_msg_stats(response['gateway'])
        yield from msg_metrics

        # Box metrics
        box_metrics = self.collect_box_stats(response['gateway']['boxes'])
        yield from box_metrics

        # Number of smsc connections
        metric = GaugeMetricFamily('bearerbox_smsc_connections',
                                    'Number of SMSC connections')
        metric.add_sample('bearerbox_smsc_connections',
                          value=int(response['gateway']['smscs']['count']),
                          labels={})
        yield metric

        # SMSC metrics
        if not self.opts.disable_smsc:
            smsc_metrics = self.collect_smsc_stats(response['gateway']['smscs'])
            yield from smsc_metrics

        duration = time() - start
        metric = GaugeMetricFamily('bearerbox_scrape_duration_seconds',
                                   'Bearerbox metrics scrape duration in seconds (*)')
        metric.add_sample('bearerbox_scrape_duration_seconds', value=duration, labels={})
        yield metric


def read_password_file(path: str) -> str:
    try:
        with open(path) as pass_file:
            password = pass_file.read().strip()
    except OSError as err:
        sys.exit(f"Failed to open file {path}.\n{err}")
    except UnicodeError as err:
        sys.exit(f"Failed to read file {path}.\n{err}")

    return password


def cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kannel exporter for Prometheus")
    parser.add_argument('--target', dest='target',
                        help='Target kannel server, PROTO:HOST:PORT. ' +
                        '(default http://127.0.0.1:13000)',
                        default=os.environ.get('KANNEL_HOST', 'http://127.0.0.1:13000'))
    parser.add_argument('--port', dest='port', type=int,
                        help='Exporter port. (default 9390)',
                        default=int(os.environ.get('KANNEL_EXPORTER_PORT', '9390')))
    parser.add_argument('--timeout', dest='timeout', type=int,
                        help='Timeout for trying to get stats. (default 15)',
                        default=int(os.environ.get('KANNEL_EXPORTER_TIMEOUT', '15')))
    parser.add_argument('--disable-smsc-metrics', dest='disable_smsc', action='store_true',
                        help='Disable SMSC connections metrics')
    parser.add_argument('--collect-wdp-metrics', dest='collect_wdp', action='store_true',
                        help='Collect WDP metrics.')
    parser.add_argument('--collect-box-uptime', dest='collect_box_uptime',
                        action='store_true', help='Collect boxes uptime metrics')
    parser.add_argument('--collect-smsc-uptime', dest='collect_smsc_uptime',
                        action='store_true', help='Collect smsc uptime metrics')
    parser.add_argument('--box-connection-types', dest='box_connections',
                        nargs='+', default=['wapbox', 'smsbox'],
                        help='List of box connection types. (default wapbox, smsbox)')
    parser.add_argument('--disable-exporter-metrics', dest='disable_exporter_metrics',
                        action='store_true', help='Disable exporter metrics')
    parser.add_argument('--log-level', dest='log_level', default='WARNING',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Define the logging level')
    parser.add_argument('-v', '--version', dest='version', action='store_true',
                        help='Display version information and exit')

    pass_group = parser.add_mutually_exclusive_group()
    pass_group.add_argument('--password', dest='password',
                            help='Password of the kannel status page. Mandatory argument',
                            default=os.environ.get('KANNEL_STATUS_PASSWORD'))
    pass_group.add_argument('--password-file', dest='password_file',
                            help='File contains the kannel status password')
    return parser


def main():
    # command line arguments
    parser = cli()
    args = parser.parse_args()

    # display version and exit
    if args.version is True:
        print(f"Version is {__version__}")
        sys.exit()

    # logger configuration
    logging.basicConfig(format="%(asctime)s %(name)s %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    logger.setLevel(args.log_level)

    # check if password has been set
    status_password = None
    if args.password is None and args.password_file is None:
        parser.error('Option --password or --password-file must be set.')
    elif args.password_file:
        status_password = read_password_file(args.password_file)
    else:
        status_password = args.password

    # collector options
    opts = CollectorOpts(args.timeout, args.disable_smsc, args.collect_wdp,
                         args.collect_box_uptime, args.collect_smsc_uptime,
                         args.box_connections)

    if args.disable_exporter_metrics:  # stop exposing exporter process metrics
        REGISTRY.unregister(GC_COLLECTOR)
        REGISTRY.unregister(PROCESS_COLLECTOR)
        REGISTRY.unregister(PLATFORM_COLLECTOR)

    REGISTRY.register(KannelCollector(args.target, status_password, opts))

    app = make_wsgi_app()
    httpd = make_server('', args.port, app)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
