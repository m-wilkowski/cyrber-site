FROM python:3.12-slim

# ── All apt packages in one layer ──
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    netdiscover \
    arp-scan \
    fping \
    traceroute \
    nbtscan \
    snmp \
    onesixtyone \
    ike-scan \
    libimage-exiftool-perl \
    libwww-perl \
    && rm -rf /var/lib/apt/lists/*

# ── Pinned tool versions (avoid GitHub API rate limits in CI) ──
ARG NUCLEI_VERSION=3.7.0
ARG SUBFINDER_VERSION=2.12.0
ARG HTTPX_VERSION=1.8.1
ARG NAABU_VERSION=2.4.0
ARG KATANA_VERSION=1.4.0
ARG DNSX_VERSION=1.2.3
ARG GOBUSTER_VERSION=3.8.2
ARG AMASS_VERSION=5.0.1
ARG PHONEINFOGA_VERSION=2.11.0

# nikto (git clone)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl
# gobuster
RUN curl -L "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /tmp && \
    mv /tmp/gobuster /usr/local/bin/gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm -rf /tmp/gobuster* /tmp/LICENSE /tmp/README.md
# whatweb (git clone)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /opt/whatweb/whatweb
# theHarvester (4.6.0 supports Python 3.11+; latest requires 3.12+)
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@4.6.0
# testssl
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
ENV TESTSSL_PATH=/opt/testssl/testssl.sh
# nuclei
RUN curl -L "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
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
RUN curl -L "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.tar.gz" \
    -o /tmp/amass.tar.gz && \
    tar xzf /tmp/amass.tar.gz -C /tmp && \
    mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64
# wpscan
RUN gem install wpscan --no-document
# sherlock (username OSINT)
RUN pip install --no-cache-dir sherlock-project
# holehe (email account check)
RUN pip install --no-cache-dir holehe
# maigret (username OSINT across 2500+ sites)
RUN pip install --no-cache-dir maigret
# metagoofil (metadata extraction from public docs)
RUN git clone --depth 1 https://github.com/opsdisk/metagoofil.git /opt/metagoofil && \
    pip install --no-cache-dir -r /opt/metagoofil/requirements.txt 2>/dev/null || true && \
    ln -s /opt/metagoofil/metagoofil.py /usr/local/bin/metagoofil && \
    chmod +x /opt/metagoofil/metagoofil.py
# phoneinfoga
RUN curl -L "https://github.com/sundowndev/phoneinfoga/releases/download/v${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz" -o /tmp/phoneinfoga.tar.gz && \
    tar xzf /tmp/phoneinfoga.tar.gz -C /tmp && \
    mv /tmp/phoneinfoga /usr/local/bin/phoneinfoga && \
    chmod +x /usr/local/bin/phoneinfoga && \
    rm -rf /tmp/phoneinfoga*
# wapiti (web application vulnerability scanner)
RUN pip install wapiti3 --break-system-packages
# joomscan (Joomla vulnerability scanner)
RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/joomscan && \
    chmod +x /opt/joomscan/joomscan.pl && \
    ln -s /opt/joomscan/joomscan.pl /usr/local/bin/joomscan
# cmsmap (multi-CMS vulnerability scanner)
RUN git clone --depth 1 https://github.com/Dionach/CMSmap.git /opt/cmsmap && \
    (test -f /opt/cmsmap/requirements.txt && pip install -r /opt/cmsmap/requirements.txt --break-system-packages || true) && \
    ln -s /opt/cmsmap/cmsmap.py /usr/local/bin/cmsmap && \
    chmod +x /opt/cmsmap/cmsmap.py
# droopescan (Drupal/Joomla/WordPress/SilverStripe/Moodle scanner)
RUN pip install droopescan --break-system-packages
# subfinder (passive subdomain enumeration by ProjectDiscovery)
RUN curl -L "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip subfinder -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip
# httpx (HTTP probing and technology detection by ProjectDiscovery)
RUN curl -L "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip
# naabu (fast port scanner by ProjectDiscovery)
RUN curl -L "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" -o /tmp/naabu.zip && \
    unzip /tmp/naabu.zip naabu -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/naabu && \
    rm /tmp/naabu.zip
# katana (web crawler by ProjectDiscovery)
RUN curl -L "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" -o /tmp/katana.zip && \
    unzip /tmp/katana.zip katana -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm /tmp/katana.zip
# dnsx (DNS toolkit by ProjectDiscovery)
RUN curl -L "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" -o /tmp/dnsx.zip && \
    unzip /tmp/dnsx.zip dnsx -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/dnsx && \
    rm /tmp/dnsx.zip
# netexec (SMB/WinRM/LDAP/MSSQL network enumeration)
RUN pip install netexec --break-system-packages || \
    (git clone --depth 1 https://github.com/Pennyw0rth/NetExec.git /opt/netexec && \
    cd /opt/netexec && pip install . --break-system-packages) || true
# bloodhound-python (Active Directory enumeration collector)
RUN pip install bloodhound --break-system-packages
# responder (LLMNR/NBT-NS/MDNS poisoner — used in analyze mode for detection)
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/responder
# fierce (DNS reconnaissance and zone transfer scanner)
RUN pip install fierce --break-system-packages
# smbmap (SMB share enumeration and access checking)
RUN pip install smbmap --break-system-packages
# sslyze (SSL/TLS configuration analysis and vulnerability scanning)
RUN pip install sslyze --break-system-packages
# searchsploit (exploit-db CLI search tool)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
# impacket (Active Directory attack toolkit — Kerberoasting, AS-REP, secretsdump, lookupsid)
RUN pip install impacket --break-system-packages
# retire.js (vulnerable JavaScript library detection)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g retire && \
    rm -rf /var/lib/apt/lists/*
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
