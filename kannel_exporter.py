#!/usr/bin/env python3

"""Prometheus custom collector for Kannel gateway
https://github.com/apostvav/kannel_exporter"""

__version__ = '0.3.3'

import argparse
import logging
import os
import sys
from urllib.request import urlopen
from urllib.error import URLError
from re import findall
from collections import namedtuple, OrderedDict
from wsgiref.simple_server import make_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import REGISTRY, make_wsgi_app
import xmltodict

# logger
logger = logging.getLogger('kannel_exporter')  # pylint: disable=invalid-name


def uptime_to_secs(uptime):
    uptime = findall(r'\d+', uptime)
    days_in_secs = int(uptime[0]) * 86400
    hours_in_secs = int(uptime[1]) * 3600
    minutes_in_secs = int(uptime[2]) * 60
    secs = int(uptime[3])
    return days_in_secs + hours_in_secs + minutes_in_secs + secs


def bearerbox_version(version):
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


CollectorOpts = namedtuple('CollectorOpts', ['filter_smsc', 'collect_wdp',
                                             'collect_box_uptime', 'collect_smsc_uptime',
                                             'box_connections'])
CollectorOpts.__new__.__defaults__ = (False, False, False, False, ['wapbox', 'smsbox'])


class KannelCollector:
    def __init__(self, target, password, opts=CollectorOpts()):
        self._target = target
        self._password = password
        self._opts = opts

    def parse_kannel_status(self):
        url = self._target + "/status.xml?password=" + self._password
        status = None
        xml = None

        try:
            with urlopen(url) as request:
                xml = request.read()
            if xml is not None:
                status = xmltodict.parse(xml, postprocessor=_xmlpostproc)

            if status['gateway'] == 'Denied':
                logger.error("Authentication failed.")
                return None

        except ValueError as err:
            logger.error("Uknown URL type: %s. Error: %s", url, err)
        except URLError as err:
            logger.error("Failed to open target URL: %s. Error: %s", url, err)
        except xmltodict.expat.ExpatError as err:
            logger.error("Failed to parse status XML. Error: %s", err)

        return status

    def collect_msg_stats(self, gw_metrics):
        metrics = OrderedDict()

        message_type = ['sms', 'dlr']
        if self._opts.collect_wdp is True:
            message_type = ['wdp'] + message_type

        for type_ in message_type:
            for key, value in gw_metrics[type_].items():
                if isinstance(value, dict):
                    for key2, value2 in value.items():
                        metric_name = 'bearerbox_{0}_{1}_{2}'.format(type_, key, key2)
                        if key2 == 'total':
                            metric_help = 'Total number of {0} {1}'.format(type_.upper(), key)
                            metrics[metric_name] = CounterMetricFamily(metric_name, metric_help)
                        else:
                            metric_help = 'Number of {0} {1} in queue'.format(key, type_.upper())
                            metrics[metric_name] = GaugeMetricFamily(metric_name, metric_help)

                        metrics[metric_name].add_sample(metric_name, value=int(value2), labels={})

                elif key not in ['inbound', 'outbound']:
                    metric_name = 'bearerbox_{0}_{1}'.format(type_, key)
                    metric_value = value
                    metric_labels = {}

                    if type_ == 'sms' and key == 'storesize':
                        metric_help = 'Number of SMS in storesize'
                    elif type_ == 'dlr':
                        if key == 'queued':
                            metric_help = 'Number of DLRs in queue'
                        elif key == 'storage':
                            metric_help = 'DLR storage type info'
                            metric_value = 1
                            metric_labels = {'storage': value}

                    metrics[metric_name] = GaugeMetricFamily(metric_name, metric_help)
                    metrics[metric_name].add_sample(metric_name, value=int(metric_value),
                                                    labels=metric_labels)

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

    @staticmethod
    def _collect_smsc_uptime(smsc_details, uptime):
        # Helper method to collect smsc uptime metrics.
        # For multiple smscs with the same id,
        # only the lowest uptime value will be exposed.
        uptime = findall(r'\d+', uptime)

        if not uptime:
            return 0

        uptime = uptime[0]

        if 'uptime' not in smsc_details or uptime < smsc_details['uptime']:
            return uptime

        return smsc_details['uptime']

    def collect_box_stats(self, box_metrics):
        metrics = OrderedDict()
        box_connections = {b: 0 for b in self._opts.box_connections}
        box_details = {}
        metrics['box_connections'] = GaugeMetricFamily('bearerbox_box_connections',
                                                       'Number of box connections')
        metrics['box_queue'] = GaugeMetricFamily('bearerbox_box_queue',
                                                 'Number of messages in box queue')

        if self._opts.collect_box_uptime is True:
            metrics['box_uptime'] = GaugeMetricFamily('bearerbox_box_uptime_seconds',
                                                      'Box uptime in seconds (*)')

        if box_metrics != '':
            # when there's only one box connected on the gateway
            # xmltodict returns an OrderedDict instead of a list of OrderedDicts
            if not isinstance(box_metrics['box'], list):
                box_metrics['box'] = [box_metrics['box']]

            for box in box_metrics['box']:
                box_connections[box['type']] = box_connections.get(box['type'], 0) + 1

                # some type of boxes (e.g wapbox) don't have IDs.
                box['id'] = box.get('id', "")

                tuplkey = (box['type'], box['id'], box['IP'])

                # some type of boxes (e.g wapbox) don't have queues.
                if 'queue' in box:
                    if tuplkey not in box_details:
                        box_details[tuplkey] = {}
                    box_details[tuplkey]['queue'] = (box_details[tuplkey].get('queue', 0)
                                                     + int(box['queue']))

                # collect box uptime metrics
                if self._opts.collect_box_uptime is True:
                    self._collect_box_uptime(box_details, box, tuplkey)

        for key, value in box_connections.items():
            metrics['box_connections'].add_sample('bearerbox_box_connections',
                                                  value=value, labels={'type': key})

        for key, value in box_details.items():
            box_labels = {'type': key[0], 'id': key[1], 'ipaddr': key[2]}
            if 'queue' in value:
                metrics['box_queue'].add_sample('bearerbox_box_queue',
                                                value=value['queue'],
                                                labels=box_labels)
            if self._opts.collect_box_uptime is True:
                metrics['box_uptime'].add_sample('bearerbox_box_uptime_seconds',
                                                 value=value['uptime'],
                                                 labels=box_labels)

        return metrics

    def collect_smsc_stats(self, smsc_count, smsc_metrics):
        metrics = OrderedDict()
        metrics['smsc_count'] = GaugeMetricFamily('bearerbox_smsc_connections',
                                                  'Number of SMSC connections')
        metrics['smsc_count'].add_sample('bearerbox_smsc_connections',
                                         value=int(smsc_count),
                                         labels={})

        if not self._opts.filter_smsc:
            metrics['failed'] = CounterMetricFamily('bearerbox_smsc_failed_messages_total',
                                                    'Total number of SMSC failed messages',
                                                    labels=["smsc_id"])
            metrics['queued'] = GaugeMetricFamily('bearerbox_smsc_queued_messages',
                                                  'Number of SMSC queued messages',
                                                  labels=["smsc_id"])
            metrics['sms_received'] = CounterMetricFamily('bearerbox_smsc_received_sms_total',
                                                          'Total number of received SMS by SMSC',
                                                          labels=["smsc_id"])
            metrics['sms_sent'] = CounterMetricFamily('bearerbox_smsc_sent_sms_total',
                                                      'Total number of SMS sent to SMSC',
                                                      labels=["smsc_id"])
            metrics['dlr_received'] = CounterMetricFamily('bearerbox_smsc_received_dlr_total',
                                                          'Total number of DLRs received by SMSC',
                                                          labels=["smsc_id"])
            metrics['dlr_sent'] = CounterMetricFamily('bearerbox_smsc_sent_dlr_total',
                                                      'Total number of DLRs sent to SMSC',
                                                      labels=["smsc_id"])
            if self._opts.collect_smsc_uptime is True:
                metrics['uptime'] = GaugeMetricFamily('bearerbox_smsc_uptime_seconds',
                                                      'SMSC uptime in seconds (*)',
                                                      labels=["smsc_id"])

            # when there's only one smsc connection on the gateway
            # xmltodict returns an OrderedDict instead of a list of OrderedDicts
            if not isinstance(smsc_metrics, list):
                smsc_metrics = [smsc_metrics]

            # Group SMSC metrics by smsc-id
            aggreg = OrderedDict()

            for smsc in smsc_metrics:
                smscid = smsc['id']

                if smscid not in aggreg:
                    aggreg[smscid] = OrderedDict()
                    aggreg[smscid]['sms'] = OrderedDict()
                    aggreg[smscid]['dlr'] = OrderedDict()

                aggreg[smscid]['failed'] = aggreg[smscid].get('failed', 0) + int(smsc['failed'])
                aggreg[smscid]['queued'] = aggreg[smscid].get('queued', 0) + int(smsc['queued'])
                if self._opts.collect_smsc_uptime is True:
                    aggreg[smscid]['uptime'] = self._collect_smsc_uptime(aggreg[smscid],
                                                                         smsc['status'])

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

            for smsc in aggreg:
                metrics['failed'].add_metric([smsc], aggreg[smsc]['failed'])
                metrics['queued'].add_metric([smsc], aggreg[smsc]['queued'])
                metrics['sms_received'].add_metric([smsc], aggreg[smsc]['sms']['received'])
                metrics['sms_sent'].add_metric([smsc], aggreg[smsc]['sms']['sent'])
                metrics['dlr_received'].add_metric([smsc], aggreg[smsc]['dlr']['received'])
                metrics['dlr_sent'].add_metric([smsc], aggreg[smsc]['dlr']['sent'])
                if self._opts.collect_smsc_uptime is True:
                    metrics['uptime'].add_metric([smsc], aggreg[smsc]['uptime'])

        return metrics

    def collect(self):  # pylint: disable=inconsistent-return-statements
        # bearerbox server status
        metric = GaugeMetricFamily('bearerbox_up',
                                   'Could the bearerbox server be reached')

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
        metrics = self.collect_msg_stats(response['gateway'])
        for metric in metrics.values():
            yield metric

        # Box metrics
        metrics = self.collect_box_stats(response['gateway']['boxes'])
        for metric in metrics.values():
            yield metric

        # SMSC metrics
        metrics = self.collect_smsc_stats(response['gateway']['smscs']['count'],
                                          response['gateway']['smscs']['smsc'])
        for metric in metrics.values():
            yield metric


def get_password(password, password_file):
    if password_file is not None:
        try:
            with open(password_file) as pass_file:
                status_password = pass_file.read().strip()
        except OSError as err:
            sys.exit("Failed to open file {0}.\n{1}".format(password_file, err))
        except UnicodeError as err:
            sys.exit("Failed to read file {0}.\n{1}".format(password_file, err))
    else:
        status_password = password
    return status_password


def cli():
    parser = argparse.ArgumentParser(description="Kannel exporter for Prometheus")
    parser.add_argument('--target', dest='target',
                        help='Target kannel server, PROTO:HOST:PORT. ' +
                        '(default http://127.0.0.1:13000)',
                        default=os.environ.get('KANNEL_HOST', 'http://127.0.0.1:13000'))
    parser.add_argument('--port', dest='port', type=int,
                        help='Exporter port. (default 9390)',
                        default=int(os.environ.get('KANNEL_EXPORTER_PORT', '9390')))
    parser.add_argument('--filter-smscs', dest='filter_smsc', action='store_true',
                        help='Filter out SMSC metrics')
    parser.add_argument('--collect-wdp', dest='collect_wdp', action='store_true',
                        help='Collect WDP metrics.')
    parser.add_argument('--collect-box-uptime', dest='collect_box_uptime',
                        action='store_true', help='Collect boxes uptime metrics')
    parser.add_argument('--collect-smsc-uptime', dest='collect_smsc_uptime',
                        action='store_true', help='Collect smsc uptime metrics')
    parser.add_argument('--box-connection-types', dest='box_connections',
                        nargs='+', default=['wapbox', 'smsbox'],
                        help='List of box connection types. (default wapbox, smsbox)')
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
        print("Version is {0}".format(__version__))
        sys.exit()

    # check if password has been set
    if args.password is None and args.password_file is None:
        parser.error('Option --password or --password-file must be set.')

    # logger configuration
    logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                        datefmt="%Y-%m-%d %H:%M:%S")
    logger.setLevel(args.log_level)

    # get password
    status_password = get_password(args.password, args.password_file)

    # collector options
    opts = CollectorOpts(args.filter_smsc, args.collect_wdp, args.collect_box_uptime,
                         args.collect_smsc_uptime, args.box_connections)

    REGISTRY.register(KannelCollector(args.target, status_password, opts))

    app = make_wsgi_app()
    httpd = make_server('', args.port, app)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
