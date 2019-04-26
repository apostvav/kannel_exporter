# Kannel Exporter

[Kannel](http://www.kannel.org) exporter for [Prometheus](https://prometheus.io). Exposes metrics collected from the kannel status page.

## Usage
```
kannel_exporter.py [-h] [--target TARGET] [--port PORT]
                   [--filter-smscs] [--collect-wdp] [--collect-box-uptime]
                   [--box-connection-types BOX_CONNECTIONS [BOX_CONNECTIONS ...]]
                   [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-v]
                   [--password PASSWORD | --password-file PASSWORD_FILE]
```

### Arguments
```
  -h, --help             show this help message and exit
  --target TARGET        Target kannel server, PROTO:HOST:PORT
                         (default http://127.0.0.1:13000)
  --port PORT            Exporter port. (default 9390)
  --filter-smscs         Filter out SMSC metrics
  --collect-wdp          Collect WDP metrics
  --collect-box-uptime   Collect boxes uptime metrics
  --box-connection-types List of box connection types. (default wapbox, smsbox)
  --log-level LEVEL      Define the logging level
  -v, --version          Display version information and exit
  --password PASSWORD    Password of the kannel status page
  --password-file FILE   File contains the kannel status password
```

### Environment Variables
Instead of command line arguments, values can be passed using environment variables.
```
--target    KANNEL_HOST
--password  KANNEL_STATUS_PASSWORD
--port      KANNEL_EXPORTER_PORT
```

## Install
Collector is written in Python3. It is not compatible with Python2.

```
git clone https://github.com/apostvav/kannel_exporter.git
cd kannel_exporter
pip install -r requirements.txt
```

### Docker
Run exporter using docker.
```
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
and then run the commands:
```
systemctl daemon-reload
systemctl start kannel_exporter.service
systemctl enable kannel_exporter.service
```

## Contribute
Any contribution is welcome. Feel free to open issues and pull requests.

For any scraping issues you may have, please open an issue and attach the status xml file.<br />
Don't forget to strip any information that should not  be shared.  
