BINARY := rufusarm64-helper
VERSION ?= 0.4.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test vet build build-arm64 deb clean

test:
	./scripts/test.sh

vet:
	go vet ./...

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY) ./cmd/rufus-linux

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-arm64 ./cmd/rufus-linux
	sha256sum dist/$(BINARY)-arm64 > dist/$(BINARY)-arm64.sha256

deb:
	VERSION=$(VERSION) ./scripts/build-deb.sh

clean:
	rm -f dist/$(BINARY) dist/$(BINARY)-arm64 dist/$(BINARY)-arm64.sha256
	rm -f dist/rufusarm64_*_arm64.deb dist/rufusarm64_*_arm64.deb.sha256
