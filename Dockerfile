FROM python:3.9-alpine3.12

COPY requirements.txt /opt/pluto-userbeacon/requirements.txt
WORKDIR /opt/pluto-userbeacon
RUN apk add --no-cache alpine-sdk linux-headers libffi libffi-dev openssl-dev && pip install -r requirements.txt && apk --no-cache del alpine-sdk linux-headers libffi-dev
RUN pip install -r requirements.txt
ADD userbeacon /opt/pluto-userbeacon/userbeacon
ADD k8s_settings /opt/pluto-userbeacon/k8s_settings
#annoying, but until my Mac gets upgraded to support later Docker I can't use chown-in-copy :(
RUN chown -R nobody /opt/pluto-userbeacon
ENV PYTHONPATH=/opt/pluto-userbeacon
WORKDIR /opt/pluto-userbeacon
USER nobody
CMD uwsgi --http :9000 --enable-threads -L --module userbeacon.wsgi --buffer-size=8192