FROM python:3.12-slim
# The hostile service serves HTTPS with a throwaway self-signed certificate,
# generated here at build time so no key is ever committed.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /srv/tls \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=hostile.lab.invalid" \
       -keyout /srv/tls/key.pem -out /srv/tls/cert.pem 2>/dev/null
WORKDIR /srv
COPY server.py /srv/server.py
EXPOSE 80 443
CMD ["python3", "-u", "/srv/server.py"]
