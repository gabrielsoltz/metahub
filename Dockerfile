FROM alpine:3.23

WORKDIR /metahub
COPY . /metahub/

#https://pkgs.alpinelinux.org/packages?name=git&branch=v3.23
#https://pkgs.alpinelinux.org/packages?name=python3&branch=v3.23
#https://pkgs.alpinelinux.org/packages?name=py3-pip&branch=v3.23

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache \
    git \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
