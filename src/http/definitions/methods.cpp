#include <string>

namespace HTTP {
	namespace METHODS {
		using string = std::string;

		const string get	= "get";

		// methods with a request body.
		const string put	= "put";
		const string post	= "post";
		const string patch	= "patch";
	};
}


