BINARY  := xcv
INSTALL := /usr/local/bin/$(BINARY)

.PHONY: build install uninstall vet test clean

build:
	go build -o $(BINARY) .

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
