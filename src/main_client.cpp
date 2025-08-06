#include "./HTTPClient.cpp"
#include "./definitions/mime_types.cpp"
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace HTTP;

int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];

	HTTPClient client;

	int status = client.open_connection(NULL, portname);
	if(status != 0) {
		fprintf(stderr, "ERROR: failed to open connection\n");
		exit(status);
	}

	std::vector<string> paths = {
		"index_1.html",
		"/index_2.html",
		"../index_3.html",
		"/../index_4.html",
		"//index_5.html",
		"C:/index_6.html",
	};
	for(const string& path : paths) {
		http_request request;
		http_response response;
		request.method = "PUT";
		request.path = path;
		request.protocol = HTTP_PROTOCOL_1_1;
		request.body = "test string\nabc 123 :)_ _ _";
		request.headers[HEADERS::content_type] = get_mime_type(".txt");
		request.headers[HEADERS::content_length] = int_to_string(request.body.length());
		//ERROR_CODE err = client.fetch(request, response);
		//if(err != ERROR_CODE::SUCCESS) fprintf(stderr, "%s\n", ERROR_MESSAGE.at(err).c_str());
		/*
		printf("REQUEST HEAD:\n%s\n", request.head.c_str());
		printf("REQUEST BODY:\n%s\n", request.body.c_str());
		printf("RESPONSE HEAD:\n%s\n", response.head.c_str());
		printf("RESPONSE BODY:\n%s\n", response.body.c_str());
		//*/
	}
}
