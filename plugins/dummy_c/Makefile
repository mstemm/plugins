PLUGIN_INFO_H_DIR= ../../
CURL = curl

all: nlohmann/json.hpp libdummy_c.so

clean:
	rm -rf nlohmann *.so

nlohmann/json.hpp:
	rm -rf nlohmann && mkdir nlohmann && $(CURL) -sLo nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.10.2/json.hpp

libdummy_c.so: dummy.cpp
	g++ -std=c++0x -fPIC -I$(PLUGIN_INFO_H_DIR) -shared -o libdummy_c.so dummy.cpp
