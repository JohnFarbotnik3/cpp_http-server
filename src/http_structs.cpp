
#ifndef F_http_structs
#define F_http_structs

#include <map>
#include <string>

namespace HTTP {
	using std::string;

	const string	HTTP_PROTOCOL_1_1	= "HTTP/1.1";

	using header_dict = std::map<string, string>;

	struct http_request {
		string		head;
		string		body;
		string		extra_data;
		// start line.
		string		method;
		string		target;
		string		protocol;
		// headers.
		header_dict	headers;
		// extra stuff.
		string		ipstr;
	};

	struct http_response {
		string		head;
		string		body;
		string		extra_data;
		// start line.
		string	protocol = HTTP_PROTOCOL_1_1;
		int		status_code;
		// headers.
		header_dict	headers;
	};

}

#endif
