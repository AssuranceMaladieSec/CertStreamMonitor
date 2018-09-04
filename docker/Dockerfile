FROM alpine:latest

LABEL maintainer="Damonneville Thomas <thomas.damonneville__A__assurance-maladie.fr>"

ENV INITSYSTEM=on

# install packages
RUN apk --no-cache add --update \
git \
python3 \
sqlite \
openrc \
supervisor \
tor

# Clone the project files into the docker container and install it
RUN git clone https://github.com/AssuranceMaladieSec/CertStreamMonitor.git /opt/CertStreamMonitor
RUN pip3 install --upgrade pip
WORKDIR /opt/CertStreamMonitor/
RUN pip3 install -r requirements.txt

# Add custom supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord"; "-c"; "/etc/supervisor/conf.d/supervisord.conf"]

# Make some clean
RUN rm -rf /var/cache/apk/*