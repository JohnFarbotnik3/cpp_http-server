#ifndef F_definitions_mime_types
#define F_definitions_mime_types

#include <map>
#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Configuring_server_MIME_types
https://www.iana.org/assignments/media-types/media-types.xhtml
*/
namespace HTTP {
	std::map<std::string, std::string> MIME_TYPES({
		// text
		{".txt"	, "text/plain; charset=utf-8"},
		{".html", "text/html"},
		{".css"	, "text/css"},
		{".js"	, "text/javascript; charset=utf-8"},
		{".md"	, "text/markdown"},

		// application
		{""		, "application/octet-stream"},
		{".bin"	, "application/octet-stream"},
		{".json", "application/json"},
		{".pdf"	, "application/pdf"},

		// image
		{".png"	, "image/png"},
		{".jpg"	, "image/jpeg"},
		{".jpeg", "image/jpeg"},
		{".webp", "image/webp"},
		{".svg"	, "image/svg"},
		{".gif"	, "image/gif"},
		{".avif", "image/avif"},
		{".tiff", "image/tiff"},
		{".bmp"	, "image/bmp"},
	});

	std::string get_mime_type(const std::string ext) {
		if(MIME_TYPES.contains(ext)) return MIME_TYPES.at(ext);
		printf("UNRECOGNIZED FILE EXTENSION: %s\n", ext.c_str());
		return "application/octet-stream";
	}
}

#endif
