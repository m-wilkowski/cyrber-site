FROM python:3.11-slim
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    curl \
    git \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    ruby \
    ruby-dev \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    unzip \
    smbclient \
    samba-common \
    && rm -rf /var/lib/apt/lists/*
# nikto (git clone)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl
# gobuster (binary from GitHub releases)
RUN curl -L "https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz" -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /tmp && \
    mv /tmp/gobuster /usr/local/bin/gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm -rf /tmp/gobuster* /tmp/LICENSE /tmp/README.md
# whatweb (git clone)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /opt/whatweb/whatweb
# theHarvester (4.6.0 supports Python 3.11; latest requires 3.12+)
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@4.6.0
# testssl
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
ENV TESTSSL_PATH=/opt/testssl/testssl.sh
# nuclei
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v') && \
    curl -L "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    rm /tmp/nuclei.zip
# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
# enum4linux-ng (git clone)
RUN git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng && \
    pip install --no-cache-dir -r /opt/enum4linux-ng/requirements.txt && \
    ln -s /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng && \
    chmod +x /opt/enum4linux-ng/enum4linux-ng.py
# dnsrecon
RUN pip install dnsrecon
# amass
RUN curl -L "https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.tar.gz" \
    -o /tmp/amass.tar.gz && \
    tar xzf /tmp/amass.tar.gz -C /tmp && \
    mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64
# wpscan
RUN gem install wpscan --no-document
# wordlist
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -L https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
    -o /usr/share/wordlists/dirb/common.txt
RUN mkdir -p /app/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
