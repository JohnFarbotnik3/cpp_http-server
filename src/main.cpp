#include "./HTTPServer.cpp"
#include <cstdio>
#include <cstdlib>

int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	HTTP::HTTPServer server(NULL, portname);
	server.start_listen();
}
