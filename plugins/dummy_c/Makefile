FALCOSECURITY_LIBSCAP_DIR= ../../../libs/userspace/libscap
NLOHMANN_JSON_DIR=/home/mstemm/work/falco-build/njson-prefix/src/njson/include

all: libdummy_c.so

libdummy_c.so: dummy.cpp
	g++ -fPIC -I$(NLOHMANN_JSON_DIR) -I$(FALCOSECURITY_LIBSCAP_DIR) -shared -o libdummy_c.so dummy.cpp
