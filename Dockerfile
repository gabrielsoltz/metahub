FROM alpine:3.20

WORKDIR /metahub
COPY . /metahub/

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache git=2.45.1-r0 python3=3.12.3-r1 py3-pip=24.0-r2 \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
