FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
        locales \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN useradd -m -u 1000 steam

RUN mkdir -p /opt/depotdownloader \
    && curl -sSL https://github.com/SteamRE/DepotDownloader/releases/download/DepotDownloader_3.4.0/DepotDownloader-linux-x64.zip \
        -o /tmp/depotdownloader.zip \
    && unzip -o /tmp/depotdownloader.zip -d /opt/depotdownloader \
    && rm /tmp/depotdownloader.zip \
    && chmod +x /opt/depotdownloader/DepotDownloader \
    && chown -R steam:steam /opt/depotdownloader

ENV DEPOTDOWNLOADER_PATH=/opt/depotdownloader/DepotDownloader

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/
RUN chmod +x /app/start.sh \
    && mkdir -p /data/mirror /data/mirror/steam /data/mirror/local \
    && chown -R steam:steam /data

USER steam

EXPOSE 8080

ENTRYPOINT ["/app/start.sh"]
