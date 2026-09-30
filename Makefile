# Thin wrapper over install.sh, which holds the real logic (and also runs without make,
# e.g. from Git Bash on Windows):
#   make install ROUTER=root@192.168.1.1 SSH_PORT=22
ROUTER   ?= root@192.168.1.1
SSH_PORT ?= 22
GO       ?= go
export ROUTER SSH_PORT SSH_KEY GO

test:
	$(GO) vet ./... && $(GO) test ./...

# A local arm64 build without touching a router (CI, or to inspect the binary).
build-arm64: test
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="-s -w" -o openwrt-mcp.arm64 .

build stage install:
	./install.sh $@

uninstall:
	./install.sh uninstall

clean:
	rm -f openwrt-mcp openwrt-mcp.* *.bin

.PHONY: test build-arm64 build stage install uninstall clean
