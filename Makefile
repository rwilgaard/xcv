BINARY  := xcv
INSTALL := /usr/local/bin/$(BINARY)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build install uninstall vet lint test clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/xcv

install: build
	mv $(BINARY) $(INSTALL)

uninstall:
	rm -f $(INSTALL)

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go test -race ./...

clean:
	rm -f $(BINARY)
