//#include "./HTTPServer.cpp"
#include <cstdio>
#include <cstdlib>
#include "src/utils/commandline.cpp"
#include "./handlers/static_file_server.cpp"

using std::string;
using HTTP::Handlers::static_file_server::static_file_server_config;

/*
debug:
g++ -std=c++23 -O2 fsanitize=address -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"

build:
g++ -std=c++23 -O2 -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"

run:
./bin/main_server.elf -port 5000 -config_fileserver "./config/config_static-file-server.conf"

*/

int main(const int argc, const char** argv) {
	utils::commandline::cmd_arguments args(argc, argv);
	std::vector<string> required{ "-port", "-config_fileserver" };
	for(const string& key : required) {
		if(!args.named_arguments.contains(key)) {
			printf("missing argument: %s\n", key.c_str());
			exit(EXIT_FAILURE);
		}
	}
	const string portname = args.named_arguments.at("-port");
	int status = 0;
	static_file_server_config config = static_file_server_config::from_config(utils::config_util::parse_file(args.named_arguments.at("-config_fileserver"), status));
	if(status) {
		printf("failed to parse config file.\n");
		exit(EXIT_FAILURE);
	}
	HTTP::Handlers::static_file_server::HTTPFileServer server(NULL, portname.c_str(), config);
	server.start_listen();
}
