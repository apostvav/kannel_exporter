FROM python:3.10-alpine

COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt
COPY kannel_exporter.py /usr/local/bin/

ENV KANNEL_EXPORTER_PORT "9390"
EXPOSE 9390
ENTRYPOINT [ "kannel_exporter.py" ]
