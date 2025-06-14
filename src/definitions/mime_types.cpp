#include <map>
#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Configuring_server_MIME_types
https://www.iana.org/assignments/media-types/media-types.xhtml
*/
namespace HTTP {
	std::map<std::string, std::string> MIME_TYPES(
		{
			// text
			{"txt"	, "text/plain; charset=utf-8"},
			{"html"	, "text/html"},
			{"css"	, "text/css"},
			{"js"	, "text/javascript; charset=utf-8"},
			{"md"	, "text/markdown"},

			// application
			{""		, "application/octet-stream"},
			{"json"	, "application/json"},
			{"pdf"	, "application/pdf"},

			// image
			{"png"	, "image/png"},
		}
	);
}


