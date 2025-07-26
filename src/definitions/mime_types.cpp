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
		// application
		{""		, "application/octet-stream"},
		{".bin"	, "application/octet-stream"},
		{".http", "application/http"},
		{".json", "application/json"},
		{".pdf"	, "application/pdf"},
		{".sql"	, "application/sql"},
		{".wasm", "application/wasm"},
		{".yaml", "application/yaml"},
		{".zip"	, "application/zip"},
		{".7z"	, "application/7z"},

		// text
		{".css"	, "text/css"},
		{".csv"	, "text/csv"},
		{".html", "text/html"},
		{".js"	, "text/javascript; charset=utf-8"},
		{".md"	, "text/markdown"},
		{".txt"	, "text/plain; charset=utf-8"},
		{".xml"	, "text/xml"},

		// font
		{".otf"	, "font/otf"},
		{".ttf"	, "font/ttf"},
		{".woff", "font/woff"},

		// image
		{".avif", "image/avif"},
		{".bmp"	, "image/bmp"},
		{".gif"	, "image/gif"},
		{".jpg"	, "image/jpeg"},
		{".jpeg", "image/jpeg"},
		{".png"	, "image/png"},
		{".svg"	, "image/svg"},
		{".tiff", "image/tiff"},
		{".webp", "image/webp"},

		// video
		{".av1"	, "video/av1"},
		{".mp4"	, "video/mp4"},
		{".ogg"	, "video/ogg"},
		{".vp8"	, "video/vp8"},
		{".vp9"	, "video/vp9"},

		// audio
		{".ogg"	, "audio/ogg"},
		{".opus", "audio/opus"},
	});

	std::string get_mime_type(const std::string ext) {
		if(MIME_TYPES.contains(ext)) return MIME_TYPES.at(ext);
		printf("UNRECOGNIZED FILE EXTENSION: %s\n", ext.c_str());
		return "application/octet-stream";
	}
}

#endif
