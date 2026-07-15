BINARY := rufus-linux
VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test vet build build-arm64 clean

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY) ./cmd/rufus-linux

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-arm64 ./cmd/rufus-linux
	sha256sum dist/$(BINARY)-arm64 > dist/$(BINARY)-arm64.sha256

clean:
	rm -f dist/$(BINARY) dist/$(BINARY)-arm64 dist/$(BINARY)-arm64.sha256
