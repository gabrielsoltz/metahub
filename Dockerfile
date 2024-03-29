FROM alpine:3.19

WORKDIR /metahub
COPY . /metahub/

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache git=2.43.0-r0 python3=3.11.8-r0 py3-pip=23.3.1-r0 \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
