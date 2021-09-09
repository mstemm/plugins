SHELL=/bin/bash -o pipefail

GO ?= go

all: libjson.so

clean:
	rm -f *.h *.so

libjson.so: json.go
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libjson.so *.go

