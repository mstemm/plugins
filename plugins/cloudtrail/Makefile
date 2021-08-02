SHELL=/bin/bash -o pipefail

GO ?= go

all: libcloudtrail.so

.PHONY: libcloudtrail.so
libcloudtrail.so:
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libcloudtrail.so *.go

