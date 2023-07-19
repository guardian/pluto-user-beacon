FROM python:3.9-bookworm

COPY requirements.txt /opt/pluto-userbeacon/requirements.txt
WORKDIR /opt/pluto-userbeacon

# Update package list and install dependencies using apt-get
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    && pip install -r requirements.txt \
    && apt-get remove -y \
    build-essential \
    libffi-dev \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install -r requirements.txt

ADD userbeacon /opt/pluto-userbeacon/userbeacon
ADD k8s_settings /opt/pluto-userbeacon/k8s_settings

# The chown command remains unchanged
RUN chown -R nobody /opt/pluto-userbeacon

ENV PYTHONPATH=/opt/pluto-userbeacon

USER nobody
CMD uwsgi --http :9000 --enable-threads -L --module userbeacon.wsgi --buffer-size=8192

