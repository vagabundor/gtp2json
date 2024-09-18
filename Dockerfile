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

ENTRYPOINT ["/app/gtp2json"]