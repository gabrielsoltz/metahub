FROM alpine:3.14

COPY . metahub

WORKDIR metahub

RUN apk upgrade --no-cache busybox \
    && apk -U add --no-cache git python3 py3-pip \
    && rm -rf /var/cache/apk/* \
    && pip3 install -r requirements.txt
