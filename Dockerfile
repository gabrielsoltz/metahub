FROM alpine:3.21

WORKDIR /metahub
COPY . /metahub/

#https://pkgs.alpinelinux.org/package/edge/main/x86/git
#https://pkgs.alpinelinux.org/package/edge/main/x86/python3
#https://pkgs.alpinelinux.org/package/edge/community/x86/py3-pip

RUN apk upgrade --no-cache busybox \
    && apk add -U --no-cache \
    git=2.47.2-r0 \ 
    python3=3.12.10-r0 \
    py3-pip=24.3.1-r0 \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir -r requirements.txt --break-system-packages
