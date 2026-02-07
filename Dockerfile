FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        lib32gcc-s1 \
        lib32stdc++6 \
        lib32z1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 steam

RUN mkdir -p /opt/steamcmd \
    && curl -sSL https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz \
        | tar -xz -C /opt/steamcmd \
    && chown -R steam:steam /opt/steamcmd

ENV STEAMCMD_PATH=/opt/steamcmd/steamcmd.sh

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY *.py /app/
COPY start.sh /app/
RUN chmod +x /app/start.sh \
    && mkdir -p /data/mirror /data/mirror/steam /data/mirror/local \
    && chown -R steam:steam /data

USER steam

ENTRYPOINT ["/app/start.sh"]
