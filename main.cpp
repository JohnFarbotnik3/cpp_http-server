# include "./test_sockets.cpp"
#include <string>

int main(const int argc, const char** argv) {
	//test_address_conversions();
	//test_address_info();
	if(argc <= 1) printf("missing arg[1]: is_server (0|1)\n");
	if(argc <= 1) exit(1);
	bool is_server = std::stoi(argv[1]);
	test_socket_connect_or_listen(is_server);
}
