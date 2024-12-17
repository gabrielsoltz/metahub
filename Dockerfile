FROM alpine:3.20

WORKDIR /metahub
COPY . /metahub/

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache git=2.47.1-r0 python3=3.12.8-r1 py3-pip=24.3.1-r0 \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
