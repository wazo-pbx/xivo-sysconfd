## Image to build from sources

FROM debian:latest
MAINTAINER XiVO Team "dev@avencall.com"

ENV DEBIAN_FRONTEND noninteractive
ENV HOME /root

# Add dependencies
RUN apt-get -qq update
RUN apt-get -qq -y install \
    wget \
    apt-utils \
    python-pip \
    git \
    ssh \
    python-dev \
    libyaml-dev \
    python-dumbnet \
    python-netifaces \
    nginx \
    vim \
    curl \
    net-tools

# Install xivo-sysconfd
WORKDIR /root
RUN git clone "git://github.com/xivo-pbx/xivo-sysconfd"
WORKDIR xivo-sysconfd
RUN git checkout -t origin/switch_to_flask
RUN pip install -r requirements.txt
RUN python setup.py install

# Configure environment
RUN touch /etc/network/interfaces
RUN touch /var/log/xivo-sysconfd.log
RUN cp debian/init /etc/init.d/xivo-sysconfd
RUN mkdir -p /etc/xivo/xivo-sysconfd
RUN mkdir /var/run/xivo-sysconfd
RUN cp -a etc/xivo/xivo-sysconfd/xivo-sysconfd.yml /etc/xivo/xivo-sysconfd/

# Configure nginx
RUN cp etc/nginx/sites-available/xivo-sysconfd /etc/nginx/sites-available/xivo-sysconfd
RUN ln -s /etc/nginx/sites-available/xivo-sysconfd /etc/nginx/sites-enabled/xivo-sysconfd

# Add script to run services
ADD xivo-sysconfd-service /root/xivo-sysconfd-service
RUN chmod +x /root/xivo-sysconfd-service

# Set password
RUN echo "root:xivo" | chpasswd

# Clean
RUN apt-get clean
WORKDIR /root
RUN rm -rf xivo-sysconfd

EXPOSE 8668

CMD /root/xivo-sysconfd-service
