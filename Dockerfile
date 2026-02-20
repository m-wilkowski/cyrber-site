FROM python:3.11-slim
RUN apt-get update && apt-get install -y \
    nmap \
    gobuster \
    whatweb \
    nikto \
    masscan \
    curl \
    git \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    unzip \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# theHarvester
RUN pip install --no-cache-dir theHarvester
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
# wordlist
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -L https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
    -o /usr/share/wordlists/dirb/common.txt
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
