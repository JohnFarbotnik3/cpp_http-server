#include <map>
#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
*/
namespace HTTP {
	std::map<int, std::string> STATUS_CODES(
		{
			{ 200, "Ok"},
			{ 201, "Created"},
			{ 204, "No Content"},

			// requested resource not found.
			{ 404, "Not Found"},

			// the server doesnt know how to handle given request method.
			{ 501, "Not Implemented"},
		}
	);
}


