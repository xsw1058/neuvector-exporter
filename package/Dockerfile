FROM registry.suse.com/bci/python:3.13

ARG COMMIT
ARG VERSION

RUN python3 -m pip install -U pip setuptools
RUN python3 -m venv .venv && source .venv/bin/activate && pip3 install --upgrade pip setuptools requests urllib3
COPY startup.sh /usr/local/bin
COPY nv_exporter.py /usr/local/bin

ENTRYPOINT ["startup.sh"]
