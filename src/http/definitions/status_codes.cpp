#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
*/
namespace HTTP {
	namespace STATUS_CODES {
		using string = std::string;

		struct status {
			int		code;
			string	text;
		};

		// 2xx
		const status s200 { 200, "Ok" };
		const status s201 { 201, "Created" };
		const status s204 { 204, "No Content" };
	};
}


