#include "./HTTPServer.cpp"
#include "./handlers/static_file_server.cpp"
#include <cstdio>
#include <cstdlib>


int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	HTTP::Handlers::static_file_server::config conf{"/dev/shm/vm_private/httpserver"};
	HTTP::Handlers::static_file_server::HTTPFileServer server(NULL, portname, conf);
	server.start_listen();
}
