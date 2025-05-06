BINARY=gtp2json

.PHONY: all build clean deps docker-build extract run shell

all: build

deps:
	go mod tidy

build: deps docker-build extract

docker-build:
	sudo docker build -t gtp2json .

extract:
	@echo "Extracting binary from Docker container..."
	CONTAINER_ID=$$(sudo docker create gtp2json) && \
	sudo docker cp $$CONTAINER_ID:/app/$(BINARY) ./$(BINARY) && \
	sudo docker rm $$CONTAINER_ID

run:
	sudo docker run --rm gtp2json

test:
	go test ./...

shell:
	sudo docker run --rm -it --entrypoint /bin/sh gtp2json

clean:
	rm -f $(BINARY)
