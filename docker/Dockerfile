FROM alpine:3.19

LABEL maintainer="Damonneville Thomas <thdamon__A__gmail.com>"

ENV INITSYSTEM=on

# install packages
RUN apk --no-cache add --update \
git \
python3 \
sqlite \
openrc \
supervisor \
gcc \
python3-dev \
musl-dev \
libffi-dev \
openssl-dev \
py3-pip \
cargo \
tor

# Clone the project files into the docker container and install it
COPY / /opt/CertStreamMonitor

# Activate python virtual environment
RUN python3 -m venv /opt/venv

WORKDIR /opt/CertStreamMonitor/
RUN /opt/venv/bin/python3 -m pip install --upgrade pip
RUN /opt/venv/bin/pip install -r requirements.txt

# Add custom supervisor config
COPY docker/supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord"; "-c"; "/etc/supervisor/conf.d/supervisord.conf"]

# Make some clean
RUN rm -rf /var/cache/apk/*
