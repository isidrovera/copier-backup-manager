FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip rclone restic && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/cbm
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -u 10001 -m cbm && mkdir -p /data /sources && chown -R cbm:cbm /data
USER cbm
ENV CBM_DATA=/data CBM_SOURCES=/sources XDG_CACHE_HOME=/data/cache PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--workers","1"]
