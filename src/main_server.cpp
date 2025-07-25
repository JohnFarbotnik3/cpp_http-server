//#include "./HTTPServer.cpp"
#include "./handlers/static_file_server.cpp"
#include <cstdio>
#include <cstdlib>

/*
build:
g++ -std=c++23 -O2 -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"

run:
./bin/main_server.elf 5000

*/

int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	HTTP::Handlers::static_file_server::static_file_server_config config;
	config.prefix = "/home/user/Downloads/test";
	HTTP::Handlers::static_file_server::HTTPFileServer server(NULL, portname, config);
	server.start_listen();
}
