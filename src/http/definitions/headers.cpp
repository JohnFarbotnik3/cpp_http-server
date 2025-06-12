#include <string>
/*
NOTE: HTTP headers are case-insensitive strings followed by a colon (":").
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

https://developer.mozilla.org/en-US/docs/Glossary/Request_header
https://developer.mozilla.org/en-US/docs/Glossary/Response_header
https://developer.mozilla.org/en-US/docs/Glossary/Representation_header
*/
namespace HTTP {
	/*



	*/
	namespace HEADERS {
		using string = std::string;

		// request headers.
		const string host = "host";
		const string accept = "accept";
		const string user_agent = "user-agent";

		// response headers.
		const string date	= "date";	// date when response was generated.
		const string server	= "server";	// information about server.
		const string cache_control	= "cache-control";

		// representation headers.
		const string content_type = "content-type";
		const string content_length = "content-length";
	};
}


