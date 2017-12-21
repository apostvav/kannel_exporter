# Kannel Exporter

[Kannel](http://www.kannel.org) exporter for [Prometheus](https://prometheus.io). Exposes metrics collected from the kannel status page.

## Usage
```
kannel_exporter.py [-h] [--target TARGET] [--port PORT] [--filter-smscs] [-v]
    [--password PASSWORD | --password-file PASSWORD_FILE]
```

### Arguments
```
  -h, --help            show this help message and exit
  --target TARGET       Target kannel server, PROTO:HOST:PORT. (default http://127.0.0.1:13000)
  --port PORT           Exporter port. (default 9390)
  --filter-smscs        Filter out SMSC metrics
  -v, --version         Display version information and exit
  --password PASSWORD   Password of the kannel status page. Mandatory argument
  --password-file PASSWORD_FILE
                        File contains the password the kannel status page.
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
docker run -d -p 9390:9390 apostvav/kannel_exporter --password-file=PASSWORD_FILE
```
