FROM golang:1.20-alpine as builder

RUN apk add --no-cache build-base libpcap-dev

COPY . /src
WORKDIR /src

RUN CGO_ENABLED=1 CC=gcc go build -ldflags '-w -extldflags "-static"' -o /src/gtp2json ./cmd/main.go

FROM alpine:latest

RUN mkdir -p /app

WORKDIR /app
COPY testdata.pcap /app/testdata.pcap
COPY --from=builder /src/gtp2json /app/gtp2json

ENV DOCKERIZE_VERSION v0.7.0

RUN apk update --no-cache \
    && apk add --no-cache wget openssl \
    && wget -O - https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz | tar xzf - -C /usr/local/bin \
    && apk del wget

ENTRYPOINT ["/usr/local/bin/dockerize", "-wait", "tcp://kafka:9092", "-timeout", "60s", "/app/gtp2json"]