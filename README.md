# Kannel Exporter

<p align="left">
  <a href="https://github.com/apostvav/kannel_exporter"><img alt="GitHub Actions status" src="https://github.com/apostvav/kannel_exporter/workflows/Python%20package/badge.svg"></a>
</p>

[Kannel](http://www.kannel.org) exporter for [Prometheus](https://prometheus.io). Exposes metrics collected from the kannel status page.

Works with Kannel 1.4.4 or greater.

:warning: To avoid high cardinality issues, consider using the `--disable-smsc-metrics` flag or dropping metrics on the Prometheus server for big setups.

## Usage
```
kannel_exporter.py [-h] [--target TARGET] [--port PORT]
                   [--timeout SECONDS] [--disable-smsc-metrics] [--collect-wdp-metrics]
                   [--collect-box-uptime] [--collect-smsc-uptime]
                   [--box-connection-types BOX_CONNECTIONS [BOX_CONNECTIONS ...]]
                   [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-v]
                   [--password PASSWORD | --password-file PASSWORD_FILE]
```

### Arguments
```
  -h, --help                 Show this help message and exit
  --target TARGET            Target kannel server, PROTO:HOST:PORT
                             (default http://127.0.0.1:13000)
  --port PORT                Exporter port. (default 9390)
  --timeout SECONDS          Timeout for trying to get stats. (default 15)
  --disable-smsc-metrics     Disable SMSC connections metrics
  --collect-wdp-metrics      Collect WDP metrics
  --collect-box-uptime       Collect boxes uptime metrics
  --collect-smsc-uptime      Collect SMSCs uptime metrics
  --box-connection-types     List of box connection types. (default wapbox, smsbox)
  --disable-exporter-metrics Disable exporter metrics
  --log-level LEVEL          Define the logging level
  -v, --version              Display version information and exit
  --password PASSWORD        Password of the kannel status page
  --password-file FILE       File contains the kannel status password
```

### Environment Variables
Instead of command line arguments, values can be passed using environment variables.
```
--target    KANNEL_HOST
--password  KANNEL_STATUS_PASSWORD
--port      KANNEL_EXPORTER_PORT
--timeout   KANNEL_EXPORTER_TIMEOUT
```

## Install
Exporter requires Python 3.6 or greater.

```bash
git clone https://github.com/apostvav/kannel_exporter.git
cd kannel_exporter
pip install -r requirements.txt
```

### Docker
Run exporter using docker.
```bash
docker pull apostvav/kannel_exporter
docker run -d -p 9390:9390 apostvav/kannel_exporter
```

### Run as a service
If you're on a systemd distro, create file */etc/systemd/system/kannel_exporter.service* with content:
```
[Unit]
Description=Kannel Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=<USER>
Group=<GROUP>
ExecStart=/path/to/kannel_exporter.py --password-file /path/to/secret

[Install]
WantedBy=multi-user.target
```
and then run commands:
```bash
systemctl daemon-reload
systemctl start kannel_exporter.service
systemctl enable kannel_exporter.service
```

## Contribute
Any contribution is welcome. Feel free to open issues and pull requests.

For any scraping issues you may have, please open an issue and attach the status xml file.<br />
Don't forget to strip any information that should not be shared.
