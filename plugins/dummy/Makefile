SHELL=/bin/bash -o pipefail

GO ?= go

all: libdummy.so

clean:
	rm -f *.so *.h

libdummy.so: dummy.go
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libdummy.so *.go

