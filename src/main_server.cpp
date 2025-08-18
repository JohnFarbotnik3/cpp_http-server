//#include "./HTTPServer.cpp"
#include <cstdio>
#include <cstdlib>
#include "src/utils/commandline.cpp"
#include "./handlers/static_file_server.cpp"

using std::string;
using HTTP::Handlers::static_file_server::static_file_server_config;

/*
debug:
g++ -std=c++23 -O2 -fsanitize=address -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"
g++ -std=c++23 -O2 -fsanitize=address -lssl -lcrypto -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"

build:
g++ -std=c++23 -O2 -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"
g++ -std=c++23 -O2 -lssl -lcrypto -I "./" -o "./bin/main_server.elf" "./src/main_server.cpp"

run:
./bin/main_server.elf -port 5000 -config_fileserver "./config/config_static-file-server.conf" -config_tls "./config/config_tls.conf"

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
	const string path_config_sfs = args.named_arguments.at("-config_fileserver");
	const std::map<string, string> config_sfs = utils::config_util::parse_file(path_config_sfs, status);
	if(status) {
		printf("failed to parse config file: %s\n", path_config_sfs.c_str());
		exit(EXIT_FAILURE);
	}

	static_file_server_config config = static_file_server_config::from_config(config_sfs);
	HTTP::Handlers::static_file_server::HTTPFileServer server("", portname.c_str(), 8, config);

	if(args.named_arguments.contains("-config_tls")) {
		const string path_config_tls = args.named_arguments.at("-config_tls");
		const std::map<string, string> config_tls = utils::config_util::parse_file(path_config_tls, status);
		if(status) {
			printf("failed to parse config file: %s\n", path_config_sfs.c_str());
			exit(EXIT_FAILURE);
		}
		const string path_cert = utils::config_util::parse_string(config_tls.at("path_cert"));
		const string path_pkey = utils::config_util::parse_string(config_tls.at("path_pkey"));
		server.start_listen_TLS(path_cert, path_pkey);
	} else {
		server.start_listen(false);
	}
}
