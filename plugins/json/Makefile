SHELL=/bin/bash -o pipefail

GO ?= go

all: libjson.so

.PHONY: libjson.so
libjson.so:
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libjson.so *.go

