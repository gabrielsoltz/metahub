FROM alpine:3.23

WORKDIR /metahub
COPY . /metahub/

#https://pkgs.alpinelinux.org/package/edge/main/x86/git
#https://pkgs.alpinelinux.org/package/edge/main/x86/python3
#https://pkgs.alpinelinux.org/package/edge/main/x86/py3-pip

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache \
    git=2.53.0-r0 \ 
    python3=3.14.3 \
    py3-pip=26.0.1-r0 \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
