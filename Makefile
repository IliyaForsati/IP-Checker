BINARY := ipcheckerd
PREFIX := /usr/local
CONFDIR := /etc/ip-checker
UNITDIR := /etc/systemd/system

.PHONY: build test vet fmt install uninstall

build:
	go build -o $(BINARY) ./cmd/ipcheckerd

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

install: build
	install -Dm755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -Dm644 deploy/systemd/ip-checker.service $(UNITDIR)/ip-checker.service
	mkdir -p $(CONFDIR)
	test -f $(CONFDIR)/config.json || install -Dm600 configs/config.example.json $(CONFDIR)/config.json
	systemctl daemon-reload

uninstall:
	systemctl disable --now ip-checker.service || true
	rm -f $(UNITDIR)/ip-checker.service
	rm -f $(PREFIX)/bin/$(BINARY)
	systemctl daemon-reload
