#include <filesystem>
#include <string>
#include "../http_structs.cpp"
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"
#include "../HTTPServer.cpp"
#include "../utils/file_io.cpp"

/*
TODO:
- FIX: cant PUT files into a directory that doesnt exist.
	ideally (with a config setting), the server should be able to create
	required parent directories as long as they are safe (i.e. within prefix directory).
	(this will likely require improvements to related function in "file_io.cpp")
...
*/
namespace HTTP::Handlers::static_file_server {
	using std::string;
	namespace fs = std::filesystem;
	using fs::path;
	namespace fio = utils::file_io;

	struct config {
		// prefix to append to target filepaths.
		// requested files should be inside this directory.
		path prefix;
	};

	http_response handle_request(const http_request& request, const config& conf) {
		http_response response;

		// by default no content is returned (overwrite header as needed).
		response.headers[HTTP::HEADERS::content_length] = "0";

		// get target file path.
		path target;
		if(request.target == "/") {
			target = path(conf.prefix / "index.html");
		} else {
			string str = request.target;
			if(str.starts_with("/")) str = str.substr(1);
			target = path(conf.prefix / str);
		}

		// security: ensure target file is within prefix directory.
		{
			bool is_safe = fio::is_target_file_within_directory(conf.prefix, target, true);
			if(!is_safe) {
				response.status_code = 404;
				return response;
			} else {
				printf("\ttarget: %s\n", target.c_str());
			}
		}

		if(request.method == HTTP::METHODS::GET) {
			if(!fio::can_read_file(target)) {
				response.status_code = 404;
				return response;
			}
			int status;
			const string content = fio::read_file(target, status);
			if(status == 0) {
				response.status_code = 200;
				response.body = content;
				// set content type.
				string ext = target.extension();
				response.headers[HTTP::HEADERS::content_type] = get_mime_type(ext);
				response.headers[HTTP::HEADERS::content_length] = int_to_string(content.length());
				return response;
			} else {
				response.status_code = 500;
				return response;
			}
		}

		if(request.method == HTTP::METHODS::PUT) {
			if(!fio::can_write_file(target)) {
				response.status_code = 403;
				return response;
			}
			int status;
			bool file_exists = fs::is_regular_file(target);
			fio::write_file(target, status, request.body.data(), request.body.size());
			response.status_code = (status != 0) ? 500 : (file_exists ? 204 : 201);
			return response;
		}

		if(request.method == HTTP::METHODS::DELETE) {
			if(!fio::can_delete_file(target)) {
				response.status_code = 404;
				return response;
			}
			int status;
			fio::delete_file(target, status);
			response.status_code = (status != 0) ? 500 : 204;
			return response;
		}

		response.status_code = 501;
		return response;
	}

	// example server.
	struct HTTPFileServer : HTTP::HTTPServer {
		config conf;

		HTTPFileServer(const char* hostname, const char* portname, config conf) : HTTPServer(hostname, portname) {
			this->conf = conf;
		}

		ERROR_CODE handle_request(const accept_connection_struct& connection, http_request& request, http_response& response) override {
			response = static_file_server::handle_request(request, conf);
			return ERROR_CODE::SUCCESS;
		}
	};
}
