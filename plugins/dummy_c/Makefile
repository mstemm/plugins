FALCOSECURITY_LIBSCAP_DIR= ../../../libs/userspace/libscap

all: libdummy_c.so

libdummy_c.so: dummy.c
	gcc -I$(FALCOSECURITY_LIBSCAP_DIR) -shared -o libdummy_c.so dummy.c
