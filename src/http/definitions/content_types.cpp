#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Configuring_server_MIME_types
https://www.iana.org/assignments/media-types/media-types.xhtml
*/
namespace HTTP {
	namespace CONTENT_TYPES {
		using string = std::string;

		// text.
		const string text		= "text/plain";
		const string html		= "text/html";
		const string css		= "text/css";
		const string javascript	= "text/javascript; charset=utf-8";
		const string markdown	= "text/markdown";

		// application.
		const string json	= "application/json";
		const string binary	= "application/octet-stream";
		const string pdf	= "application/pdf";

		// image.
		const string png	= "image/png";
	};
}


