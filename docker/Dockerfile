FROM alpine:3.13.5

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
RUN pip3 install --upgrade pip wheel
WORKDIR /opt/CertStreamMonitor/
RUN pip3 install -r requirements.txt

# Add custom supervisor config
COPY docker/supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord"; "-c"; "/etc/supervisor/conf.d/supervisord.conf"]

# Make some clean
RUN rm -rf /var/cache/apk/*
