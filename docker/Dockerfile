FROM phusion/baseimage:0.10.1

LABEL maintainer="Damonneville Thomas <thomas.damonneville__A__assurance-maladie.fr>"

CMD ["/sbin/my_init"]

# install packages
RUN apt-get update && apt-get -fy upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get install -fy \
supervisor \
git \
python3 \
python3-pip \
tor

# Clone the project files into the docker container and install it
RUN git clone https://github.com/AssuranceMaladieSec/CertStreamMonitor.git /opt/CertStreamMonitor
RUN pip3 install --upgrade pip
WORKDIR /opt/CertStreamMonitor/
RUN pip3 install -r requirements.txt

# Add custom supervisor config
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord"]

# Make some clean
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*