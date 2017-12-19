#!/usr/bin/env python3

# Prometheus custom collector for Kannel gateway
# https://github.com/apostvav/kannel_exporter

import argparse
import time
import os
from urllib.request import urlopen
from urllib.error import URLError
from re import findall
from collections import OrderedDict
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
import xmltodict


def uptime_to_secs(uptime):
    uptime = findall('\d+', uptime)
    days_in_secs = int(uptime[0]) * 86400
    hours_in_secs = int(uptime[1]) * 3600
    minutes_in_secs = int(uptime[2]) * 60
    secs = int(uptime[3])
    uptime = days_in_secs + hours_in_secs + minutes_in_secs + secs
    return uptime


class KannelCollector:
    def __init__(self, target, password, filter_smsc):
        self._target = target
        self._password = password
        self._filter_smsc = filter_smsc

    def collect(self):
        url = self._target + "/status.xml?password=" + self._password

        # bearerbox server status
        metric = GaugeMetricFamily('bearerbox_up', 'Could the bearerbox server be reached')

        try:
            response = xmltodict.parse(urlopen(url))
        except URLError as e:
            # print(e.reason)
            metric.add_sample('bearerbox_up', value=0, labels={})
            yield metric
            return []

        metric.add_sample('bearerbox_up', value=1, labels={})
        yield metric

        # Version info
        version = findall('svn-[a-z0-9]*', response['gateway']['version'])[0]
        metric = GaugeMetricFamily('bearerbox_build_info',
            'Kannel bearerbox version info')
        metric.add_sample('bearerbox_build_info',
            value=1, labels={'version': version})
        yield metric

        # Counter for the bearerbox uptime, in seconds
        uptime = uptime_to_secs(response['gateway']['status'])
        metric = GaugeMetricFamily('bearerbox_uptime_seconds',
            'Current uptime in seconds (*)')
        metric.add_sample('bearerbox_uptime_seconds',
            value=uptime, labels={})
        yield metric

        # SMS metrics
        metric = CounterMetricFamily('bearerbox_sms_received_total',
            'Total number of SMS received')
        metric.add_sample('bearerbox_sms_received_total',
            value=int(response['gateway']['sms']['received']['total']),
            labels={})
        yield metric

        metric = CounterMetricFamily('bearerbox_sms_sent_total',
            'Total number of SMS sent')
        metric.add_sample('bearerbox_sms_sent_total',
            value=int(response['gateway']['sms']['sent']['total']),
            labels={})
        yield metric

        metric = GaugeMetricFamily('bearerbox_sms_received_queued',
            'Number of received SMS in queue')
        metric.add_sample('bearerbox_sms_received_queued',
            value=int(response['gateway']['sms']['received']['queued']),
            labels={})
        yield metric

        metric = GaugeMetricFamily('bearerbox_sms_sent_queued',
            'Number of sent SMS in queue')
        metric.add_sample('bearerbox_sms_sent_queued',
            value=int(response['gateway']['sms']['sent']['queued']),
            labels={})
        yield metric

        metric = GaugeMetricFamily('bearerbox_sms_storesize',
            'Number of SMS in storesize')
        metric.add_sample('bearerbox_sms_storesize',
            value=int(response['gateway']['sms']['storesize']),
            labels={})
        yield metric

        # DLRs
        metric = CounterMetricFamily('bearerbox_dlr_received_total',
            'Total number of DLRs received')
        metric.add_sample('bearerbox_dlr_received_total',
            value=int(response['gateway']['dlr']['received']['total']),
            labels={})
        yield metric

        metric = CounterMetricFamily('bearerbox_dlr_sent_total',
            'Total number of DLRs sent')
        metric.add_sample('bearerbox_dlr_sent_total',
            value=int(response['gateway']['dlr']['sent']['total']),
            labels={})
        yield metric

        metric = GaugeMetricFamily('bearerbox_dlr_queued',
            'Number of DLRs in queue')
        metric.add_sample('bearerbox_dlr_queued',
            value=int(response['gateway']['dlr']['queued']),
            labels={})
        yield metric

        metric = GaugeMetricFamily('bearerbox_dlr_storage',
            'DLR storage type info')
        metric.add_sample('bearerbox_dlr_storage',
            value=1,
            labels={'storage': response['gateway']['dlr']['storage']})
        yield metric

        # Boxes metrics
        metric = GaugeMetricFamily('bearerbox_boxes_connected',
            'Number of boxes connected on the gateway')
        metric.add_sample('bearerbox_boxes_connected',
            value=len(response['gateway']['boxes']['box']),
            labels={})
        yield metric

        metric_uptime = CounterMetricFamily('bearerbox_box_uptime_seconds_total',
            'Box uptime in seconds (*)')
        metric_queue = GaugeMetricFamily('bearerbox_box_queue',
            'Number of messages in box queue')
        for box in response['gateway']['boxes']['box']:
            box_labels = {'type': box['type'], 'id': box['id'], 'ipaddr': box['IP']}
            metric_uptime.add_sample('bearerbox_box_uptime_seconds_total',
                value=uptime_to_secs(box['status']), labels=box_labels)
            metric_queue.add_sample('bearerbox_box_queue',
                value=int(box['queue']), labels=box_labels)

        yield metric_uptime
        yield metric_queue

        # SMSC metrics
        metric = GaugeMetricFamily('bearerbox_smsc_connections',
            'Number of SMSC connections')
        metric.add_sample('bearerbox_smsc_connections',
            value=int(response['gateway']['smscs']['count']),
            labels={})
        yield metric

        if self._filter_smsc is False:
            metric_failed = CounterMetricFamily('bearerbox_smsc_failed_messages_total',
                'Total number of SMSC failed messages', labels=["smsc-id"])
            metric_queued = GaugeMetricFamily('bearerbox_smsc_queued_messages',
                'Number of SMSC queued messages', labels=["smsc-id"])
            metric_sms_received = CounterMetricFamily('bearerbox_smsc_received_sms_total',
                'Total number of received SMS by SMSC', labels=["smsc-id"])
            metric_sms_sent = CounterMetricFamily('bearerbox_smsc_sent_sms_total',
                'Total number of SMS sent to SMSC', labels=["smsc-id"])
            metric_dlr_received = CounterMetricFamily('bearerbox_smsc_received_dlr_total',
                'Total number of DLRs received by SMSC', labels=["smsc-id"])
            metric_dlr_sent = CounterMetricFamily('bearerbox_smsc_sent_dlr_total',
                'Total number of DLRs sent to SMSC', labels=["smsc-id"])

            # Group SMSCs by smsc-id
            smsc_stats_by_id = OrderedDict()
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
                metric_failed.add_metric([smsc], smsc_stats_by_id[smsc]['failed'])
                metric_queued.add_metric([smsc], smsc_stats_by_id[smsc]['queued'])
                metric_sms_received.add_metric([smsc], smsc_stats_by_id[smsc]['sms']['received'])
                metric_sms_sent.add_metric([smsc], smsc_stats_by_id[smsc]['sms']['sent'])
                metric_dlr_received.add_metric([smsc], smsc_stats_by_id[smsc]['dlr']['received'])
                metric_dlr_sent.add_metric([smsc], smsc_stats_by_id[smsc]['dlr']['sent'])

            yield metric_failed
            yield metric_queued
            yield metric_sms_received
            yield metric_sms_sent
            yield metric_dlr_received
            yield metric_dlr_sent


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Kannel exporter for Prometheus")
    parser.add_argument('--target', dest='target',
        help='Target kannel server, PROTO:HOST:PORT. (default http://127.0.0.1:13000)',
        default=os.environ.get('KANNEL_HOST', 'http://127.0.0.1:13000'))
    parser.add_argument('--password', dest='password', required=True,
        help='Password of the kannel status page. Mandatory argument',
        default=os.environ.get('KANNEL_STATUS_PASSWORD'))
    parser.add_argument('--port', dest='port', type=int,
        help='Exporter port. (default 9390)',
        default=int(os.environ.get('KANNEL_EXPORTER_PORT', '9390')))
    parser.add_argument('--filter-smscs', dest='filter_smsc', action='store_true',
        help='Filter out SMSC metrics')
    args = parser.parse_args()

    start_http_server(args.port)
    REGISTRY.register(KannelCollector(args.target, args.password, args.filter_smsc))

    while True:
      time.sleep(1)
