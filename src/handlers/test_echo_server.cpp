#include <string>
#include <vector>
#include <chrono>
#include "../http_structs.cpp"
#include "../http_message.cpp"
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"

namespace HTTP::Handlers::test_echo_server {
	using std::string;

	http_response handle_request(const http_request& request) {
		http_response response;

		// build content.
		std::vector<string> list;
		list.push_back("==============================");
		list.push_back("start line");
		list.push_back("------------------------------");
		list.push_back(request.method);
		list.push_back(request.target);
		list.push_back(request.protocol);
		list.push_back("==============================");
		list.push_back("request headers");
		list.push_back("------------------------------");
		for(const auto& [key,val] : request.headers) {
			char temp[1024];
			int len = snprintf(temp, 1024, "%s: %s", key.c_str(), val.c_str());
			list.push_back(string(temp, len));
		}
		list.push_back("==============================");
		list.push_back("extra headers (not present in response)");
		list.push_back("------------------------------");
		header_dict extra_headers;
		{
			// milliseconds since epoch.
			char temp[256];
			const auto now = std::chrono::duration_cast<std::chrono::milliseconds, int64_t>(std::chrono::system_clock::now().time_since_epoch());
			const int64_t now_i64 = now.count();
			int len = snprintf(temp, 256, "%li", now_i64);
			extra_headers[HTTP::HEADERS::date] = string(temp, len);
		}
		for(const auto& [key,val] : extra_headers) {
			char temp[1024];
			int len = snprintf(temp, 1024, "%s: %s", key.c_str(), val.c_str());
			list.push_back(string(temp, len));
		}
		list.push_back("==============================");
		list.push_back("content");
		list.push_back("------------------------------");
		list.push_back(request.body);
		for(const string str : list) {
			response.body.append(str);
			response.body.append("\n");
		}
		response.body.append("EOF");

		// return response.
		response.status_code = 200;
		response.headers[HEADERS::content_type] = get_mime_type("txt");
		response.headers[HEADERS::content_length] = int_to_string(response.body.length());
		return response;
	}
}
