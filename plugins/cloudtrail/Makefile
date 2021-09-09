SHELL=/bin/bash -o pipefail

GO ?= go

all: libcloudtrail.so

clean:
	rm -f *.so *.h

libcloudtrail.so: cloudtrail.go
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libcloudtrail.so *.go

