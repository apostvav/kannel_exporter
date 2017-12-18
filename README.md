# Kannel Exporter

[Kannel](http://www.kannel.org) exporter for [Prometheus](https://prometheus.io). Exposes metrics collected from the kannel status page.

## Usage
```
kannel_exporter.py [-h] [--target TARGET] --password PASSWORD [--port PORT] [--filter-smscs]
```

### Arguments
```
  -h, --help           show this help message and exit
  --target TARGET      Target kannel server, PROTO:HOST:PORT. (default http://127.0.0.1:13000)
  --password PASSWORD  Password of the kannel status page. Mandatory argument
  --port PORT          Exporter port. (default 1234)
  --filter-smscs       Filter out SMSC metrics
```

### Environment Variables
Instead of command line arguments, values can be passed using environment variables.
```
--target    KANNEL_HOST
--password  KANNEL_STATUS_PASSWORD
--port      KANNEL_EXPORTER_PORT
```

## Install
Collector is written in Python3. Currently it is not compatible with Python2.

```
git clone https://github.com/apostvav/kannel_exporter.git
cd kannel_exporter
pip install -r requirements.txt
```
