FROM karalabe/xgo-latest

RUN apt-get update && apt-get install -y libpcap-dev

COPY . /src
WORKDIR /src

RUN go build -ldflags '-w -extldflags "-static"' -o gtp2json ./cmd/main.go
