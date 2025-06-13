#include <map>
#include <string>
#include "./definitions/status_codes.cpp"

namespace HTTP {
	using string = std::string;

	using header_dict = std::map<string, string>;

	struct http_request {
		string		buffer;
		size_t		head_length	= 0;// length of header section.
		size_t		body_length	= 0;// length of content section (if any).
		// start line.
		string		method;
		string		target;
		string		protocol;
		// headers.
		header_dict	headers;
		// content.
		std::string_view content() const {
			return std::string_view(buffer.data() + head_length, body_length);
		}
	};

	struct http_response {
		string		buffer_head;
		string		buffer_body;
		// start line.
		string	protocol;
		int		status_code;
		// headers.
		header_dict	headers;
		// content - NOTE: this points to an associated buffer.
		char*		content_beg;
		char*		content_end;
	};
}
