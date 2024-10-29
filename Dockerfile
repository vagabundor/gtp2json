FROM golang:1.23-alpine AS builder

RUN apk add --no-cache build-base libpcap-dev

COPY . /src
WORKDIR /src

RUN go test -v ./...

RUN CGO_ENABLED=1 CC=gcc go build -ldflags '-w -extldflags "-static"' -o /src/gtp2json ./cmd/main.go

FROM alpine:latest

WORKDIR /app
COPY --from=builder /src/gtp2json /app/gtp2json
COPY testdata.pcap /app/testdata.pcap

ENTRYPOINT ["/app/gtp2json"]