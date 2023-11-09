FROM python:3.12.0-alpine3.18

WORKDIR /opt/pluto-userbeacon

# Install system dependencies
RUN apk update \
  && apk add netcat-openbsd \
  && apk add --virtual py3-pip build-base \
  && apk add --virtual python3-dev gcc libc-dev linux-headers pcre-dev

COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

COPY userbeacon /opt/pluto-userbeacon/userbeacon
COPY k8s_settings /opt/pluto-userbeacon/k8s_settings

# Set the ownership of application files
RUN chown -R nobody:nogroup /opt/pluto-userbeacon

# Set environment variables
ENV PYTHONPATH=/opt/pluto-userbeacon

# Switch to a non-root user
USER nobody

# Set the command to start uWSGI
CMD ["uwsgi", "--http", ":9000", "--enable-threads", "-L", "--module", "userbeacon.wsgi", "--buffer-size=8192"]

