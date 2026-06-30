BINARY  := xcv
INSTALL := /usr/local/bin/$(BINARY)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build install uninstall vet lint test clean release

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

release:
ifndef version
	$(error version is required, e.g., 'make release version=0.3.0')
endif
ifneq ($(shell git status --porcelain),)
	$(error Git working directory is dirty. Commit or stash changes first.)
endif
	git tag v$(version)
	git push origin main
	git push origin v$(version)
	@echo "Tagged v$(version) and pushed. GoReleaser will build and update nix-packages."
