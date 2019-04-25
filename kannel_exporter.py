#!/usr/bin/env python3

# Prometheus custom collector for Kannel gateway
# https://github.com/apostvav/kannel_exporter

__version__ = '0.2.4'

import argparse
import logging
import os
import sys
from urllib.request import urlopen
from urllib.error import URLError
from re import findall
from collections import OrderedDict
from wsgiref.simple_server import make_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import REGISTRY, make_wsgi_app
import xmltodict

# logger
logger = logging.getLogger('kannel_exporter')


def uptime_to_secs(uptime):
    uptime = findall(r'\d+', uptime)
    days_in_secs = int(uptime[0]) * 86400
    hours_in_secs = int(uptime[1]) * 3600
    minutes_in_secs = int(uptime[2]) * 60
    secs = int(uptime[3])
    uptime = days_in_secs + hours_in_secs + minutes_in_secs + secs
    return uptime


def bearerbox_version(version):
    try:
        version = version.split('\n')[0]
        # strip 'Kannel bearerbox version ' (length 25)
        if version.find('Kannel bearerbox version ') == 0:
            version = version[25:].strip('`').rstrip('\'.')
        elif version.find('Kannel-HA bearerbox version ') == 0:
            version = version[28:].strip('`').rstrip('\'.')
        else:
            logger.warning("Bearerbox version could not be found. " +
                           "Version value set to empty string.")
            version = ""
    except IndexError:
        logger.error("Failed to parse gateway version. " +
                     "Version value set to empty string.")
        version = ""
    return version


def _xmlpostproc(path, key, value):
    if value is None:
        value = ""
    return key, value


class KannelCollector:
    def __init__(self, target, password, filter_smsc, box_connections,
                 collect_wdp=False, collect_box_uptime=False):
        self._target = target
        self._password = password
        self._filter_smsc = filter_smsc
        self._collect_wdp = collect_wdp
        self._collect_box_uptime = collect_box_uptime
        self._box_connections = box_connections

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

    def collect(self):
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
        message_type = ['sms', 'dlr']
        if self._collect_wdp is True:
            message_type = ['wdp'] + message_type

        for type in message_type:
            for k, v in response['gateway'][type].items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        metric_name = 'bearerbox_{0}_{1}_{2}'.format(type, k, k2)
                        if k2 == 'total':
                            metric_help = 'Total number of {0} {1}'.format(type.upper(), k)
                            metric = CounterMetricFamily(metric_name, metric_help)
                        else:
                            metric_help = 'Number of {0} {1} in queue'.format(k, type.upper())
                            metric = GaugeMetricFamily(metric_name, metric_help)

                        metric.add_sample(metric_name, value=int(v2), labels={})
                        yield metric

                elif k not in ['inbound', 'outbound']:
                    metric_name = 'bearerbox_{0}_{1}'.format(type, k)
                    metric_value = v
                    metric_labels = {}

                    if type == 'sms' and k == 'storesize':
                        metric_help = 'Number of SMS in storesize'
                    elif type == 'dlr':
                        if k == 'queued':
                            metric_help = 'Number of DLRs in queue'
                        elif k == 'storage':
                            metric_help = 'DLR storage type info'
                            metric_value = 1
                            metric_labels = {'storage': v}

                    metric = GaugeMetricFamily(metric_name, metric_help)
                    metric.add_sample(metric_name, value=int(metric_value),
                                      labels=metric_labels)
                    yield metric

        # Box metrics
        box_connections = {b: 0 for b in self._box_connections}
        box_details = {}
        metric_box_connections = GaugeMetricFamily('bearerbox_box_connections',
                                                   'Number of box connections')
        metric_box_queue = GaugeMetricFamily('bearerbox_box_queue',
                                             'Number of messages in box queue')

        if self._collect_box_uptime is True:
            metric_box_uptime = GaugeMetricFamily('bearerbox_box_uptime_seconds',
                                                  'Box uptime in seconds (*)')
        if response['gateway']['boxes'] != '':
            # when there's only one box connected on the gateway
            # xmltodict returns an OrderedDict instead of a list of OrderedDicts
            if not isinstance(response['gateway']['boxes']['box'], list):
                response['gateway']['boxes']['box'] = [response['gateway']['boxes']['box']]

            for box in response['gateway']['boxes']['box']:
                if box['type'] in box_connections.keys():
                    box_connections[box['type']] += 1
                else:
                    box_connections[box['type']] = 1

                # some type of boxes (e.g wapbox) don't have IDs.
                if 'id' not in box.keys():
                    box['id'] = ""

                tuplkey = (box['type'], box['id'], box['IP'])

                # some type of boxs (e.g wapbox) don't have queues.
                if 'queue' in box.keys():
                    if tuplkey in box_details.keys():
                        box_details[tuplkey]['queue'] += int(box['queue'])
                    else:
                        box_details[tuplkey] = {}
                        box_details[tuplkey]['queue'] = int(box['queue'])

                # collect box uptime metrics
                # In case of multiple boxes with same type, id and host.
                # Only the uptime of the first occurence will be exposed
                # in order to avoid duplicates.
                if self._collect_box_uptime is True:
                    if tuplkey in box_details.keys():
                        if 'uptime' not in box_details[tuplkey].keys():
                            box_details[tuplkey]['uptime'] = uptime_to_secs(box['status'])
                    else:
                        box_details[tuplkey] = {}
                        box_details[tuplkey]['uptime'] = uptime_to_secs(box['status'])

        for key, value in box_connections.items():
            metric_box_connections.add_sample('bearerbox_box_connections',
                                              value=value, labels={'type': key})
        yield metric_box_connections

        for key, value in box_details.items():
            box_labels = {'type': key[0], 'id': key[1], 'ipaddr': key[2]}
            if 'queue' in value.keys():
                metric_box_queue.add_sample('bearerbox_box_queue',
                                            value=value['queue'],
                                            labels=box_labels)
            if self._collect_box_uptime is True:
                metric_box_uptime.add_sample('bearerbox_box_uptime_seconds',
                                             value=value['uptime'],
                                             labels=box_labels)

        yield metric_box_queue
        if self._collect_box_uptime is True:
            yield metric_box_uptime

        # SMSC metrics
        metric = GaugeMetricFamily('bearerbox_smsc_connections',
                                   'Number of SMSC connections')
        metric.add_sample('bearerbox_smsc_connections',
                          value=int(response['gateway']['smscs']['count']),
                          labels={})
        yield metric

        if self._filter_smsc is False:
            metric_failed = CounterMetricFamily('bearerbox_smsc_failed_messages_total',
                                                'Total number of SMSC failed messages',
                                                labels=["smsc_id", "endpoint"])
            metric_queued = GaugeMetricFamily('bearerbox_smsc_queued_messages',
                                              'Number of SMSC queued messages',
                                              labels=["smsc_id", "endpoint"])
            metric_sms_received = CounterMetricFamily('bearerbox_smsc_received_sms_total',
                                                      'Total number of received SMS by SMSC',
                                                      labels=["smsc_id", "endpoint"])
            metric_sms_sent = CounterMetricFamily('bearerbox_smsc_sent_sms_total',
                                                  'Total number of SMS sent to SMSC',
                                                  labels=["smsc_id", "endpoint"])
            metric_dlr_received = CounterMetricFamily('bearerbox_smsc_received_dlr_total',
                                                      'Total number of DLRs received by SMSC',
                                                      labels=["smsc_id", "endpoint"])
            metric_dlr_sent = CounterMetricFamily('bearerbox_smsc_sent_dlr_total',
                                                  'Total number of DLRs sent to SMSC',
                                                  labels=["smsc_id", "endpoint"])

            # Group SMSCs by smsc-id
            smsc_stats_by_id = OrderedDict()

            # when there's only one smsc connection on the gateway
            # xmltodict returns an OrderedDict instead of a list of OrderedDicts
            if not isinstance(response['gateway']['smscs']['smsc'], list):
                response['gateway']['smscs']['smsc'] = [response['gateway']['smscs']['smsc']]

            for smsc in response['gateway']['smscs']['smsc']:
                smscid = smsc['id']
                if smscid in smsc_stats_by_id:
                    smsc_stats_by_id[smscid]['failed'] += int(smsc['failed'])
                    smsc_stats_by_id[smscid]['queued'] += int(smsc['queued'])
                    smsc_stats_by_id[smscid]['sms']['received'] += int(smsc['sms']['received'])
                    smsc_stats_by_id[smscid]['sms']['sent'] += int(smsc['sms']['sent'])
                    smsc_stats_by_id[smscid]['dlr']['received'] += int(smsc['dlr']['received'])
                    smsc_stats_by_id[smscid]['dlr']['sent'] += int(smsc['dlr']['sent'])
                else:
                    smsc_stats_by_id[smscid] = OrderedDict()
                    smsc_stats_by_id[smscid]['failed'] = int(smsc['failed'])
                    smsc_stats_by_id[smscid]['queued'] = int(smsc['queued'])
                    smsc_stats_by_id[smscid]['sms'] = OrderedDict()
                    smsc_stats_by_id[smscid]['sms']['received'] = int(smsc['sms']['received'])
                    smsc_stats_by_id[smscid]['sms']['sent'] = int(smsc['sms']['sent'])
                    smsc_stats_by_id[smscid]['dlr'] = OrderedDict()
                    smsc_stats_by_id[smscid]['dlr']['received'] = int(smsc['dlr']['received'])
                    smsc_stats_by_id[smscid]['dlr']['sent'] = int(smsc['dlr']['sent'])

            for smsc in smsc_stats_by_id:
                metric_failed.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['failed'])
                metric_queued.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['queued'])
                metric_sms_received.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['sms']['received'])
                metric_sms_sent.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['sms']['sent'])
                metric_dlr_received.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['dlr']['received'])
                metric_dlr_sent.add_metric([smsc, "ocmgp://{}".format(smsc)], smsc_stats_by_id[smsc]['dlr']['sent'])

            yield metric_failed
            yield metric_queued
            yield metric_sms_received
            yield metric_sms_sent
            yield metric_dlr_received
            yield metric_dlr_sent


def get_password(password, password_file):
    if password_file is not None:
        try:
            with open(password_file) as fd:
                status_password = fd.read().strip()
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
    parser.add_argument('--box-connection-types', dest='box_connections',
                        nargs='+', default=['wapbox', 'smsbox'],
                        help='List of box connection types. (default wapbox, smsbox')
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


if __name__ == '__main__':

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
    status_password = "3AfLA8e.-ihxHM8B"
    #status_password = get_password(args.password, args.password_file)

    REGISTRY.register(KannelCollector(args.target, status_password,
                                      args.filter_smsc,
                                      args.box_connections,
                                      args.collect_wdp,
                                      args.collect_box_uptime))

    app = make_wsgi_app()
    httpd = make_server('', args.port, app)
    httpd.serve_forever()
