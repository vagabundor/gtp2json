BINARY=gtp2json

.PHONY: all build clean deps docker-build extract docker-build-minimal run shell

all: build

deps:
	go mod tidy

build: deps docker-build extract

docker-build:
	sudo docker build -t gtp2json-build .

extract:
	CONTAINER_ID=$$(sudo docker create gtp2json-build) && \
	sudo docker cp $$CONTAINER_ID:/src/gtp2json ./gtp2json && \
	sudo docker rm $$CONTAINER_ID

docker-build-minimal:
	sudo docker build -f Dockerfile.minimal -t gtp2json-minimal .

run:
	sudo docker run --rm gtp2json-minimal

test:
	go test ./...

shell:
	sudo docker run --rm -it --entrypoint /bin/sh gtp2json-minimal

clean:
	rm -f $(BINARY)
