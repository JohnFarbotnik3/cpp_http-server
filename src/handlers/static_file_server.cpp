#include <cstdlib>
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
- convert prefix directory to absolute directory during init.
- throw error during init if trying to use prefix-directory that doesnt exist.
- add setting can_create_directories (default=false) to control
	whether or not a write operation is allowed to create directories,
	or if it should throw when parent directory of file to write does not exist.
- add setting can_remove_directories (default=false), similar to above.
...

*/
namespace HTTP::Handlers::static_file_server {
	using std::string;
	namespace fio = utils::file_io;
	namespace fs = std::filesystem;
	using fs::path;

	struct static_file_server_config {
		string prefix = "";// prefix to append to target filepaths.
		bool can_get_files = false;
		bool can_put_files = false;
		bool can_delete_files = false;
	};

	struct static_file_server_struct {
		static_file_server_config config;
		path prefix_canonical;

		static_file_server_struct(static_file_server_config config) {
			printf("[static_file_server_struct] prefix=%s\n", config.prefix.c_str());
			prefix_canonical = fs::weakly_canonical(config.prefix);
			printf("[static_file_server_struct] prefix_canonical=%s\n", prefix_canonical.c_str());
			if(!fs::exists(prefix_canonical)) {
				fprintf(stderr, "prefix does not exist.\n");
				exit(EXIT_FAILURE);
			}
			if(!fs::is_directory(prefix_canonical)) {
				fprintf(stderr, "prefix is not a directory.\n");
				exit(EXIT_FAILURE);
			}
		}

		int handle_request(const http_request& request, http_response& response) {
			// by default no content is returned (overwrite header as needed).
			response.headers[HTTP::HEADERS::content_length] = "0";

			// modify target file path.
			path target;
			if(request.target == "/") {
				target = path(prefix_canonical / "index.html");
			} else {
				string str = request.target;
				if(str.starts_with("/")) str = str.substr(1);
				target = path(prefix_canonical / str);
			}

			// SECURITY: ensure target file is both valid and within prefix directory.
			std::error_code ec;
			path target_canonical = fs::weakly_canonical(target, ec);
			if(ec) {
				fprintf(stderr, "%s\n", ec.message().c_str());
				return 500;
			}
			bool is_within_directory =
				target_canonical.string().starts_with(prefix_canonical.string()) &&
				target_canonical.string().length() > prefix_canonical.string().length();
			if(!is_within_directory) {
				fprintf(stderr, "[SECURITY] target is not within prefix directory!\n\tprefix=%s\n\ttarget=%s\n", prefix_canonical.c_str(), target_canonical.c_str());
				return 404;
			}
			target = target_canonical;

			// ============================================================
			// request methods.
			// ------------------------------------------------------------

			if(config.can_get_files && request.method == HTTP::METHODS::GET) {
				bool can_read_file = fs::exists(target) && fs::is_regular_file(target);
				if(!can_read_file) return 404;
				int status;
				const string content = fio::read_file(target, status);
				if(status != 0) return 500;
				response.body = content;
				string ext = target.extension();
				response.headers[HTTP::HEADERS::content_type] = get_mime_type(ext);
				response.headers[HTTP::HEADERS::content_length] = int_to_string(content.length());
				return 200;
			}

			if(config.can_put_files && request.method == HTTP::METHODS::PUT) {
				const bool can_write_file = fs::is_directory(target.parent_path()) && (!fs::exists(target) || fs::is_regular_file(target));
				if(!can_write_file) return 405;
				int status;
				bool file_exists = fs::is_regular_file(target);
				fio::write_file(target, status, request.body.data(), request.body.size());
				return (status != 0) ? 500 : (file_exists ? 204 : 201);
			}

			if(config.can_delete_files && request.method == HTTP::METHODS::DELETE) {
				const bool can_delete_file = fs::exists(target) && fs::is_regular_file(target);
				if(!can_delete_file) return 404;
				int status;
				fio::delete_file(target, status);
				return (status != 0) ? 500 : 204;
			}

			return 501;
		}

	};

	// example server.
	struct HTTPFileServer : HTTP::HTTPServer {
		static_file_server_struct sfs;

		HTTPFileServer(const char* hostname, const char* portname, static_file_server_config config) : HTTPServer(hostname, portname), sfs(config) {}

		ERROR_CODE handle_request(const accept_connection_struct& connection, http_request& request, http_response& response) override {

			http_response resp;
			resp.status_code = sfs.handle_request(request, resp);
			response = resp;
			printf("[response] method=%s, status=%i, ip=%s, target=%s, reqlen=%lu+%lu, reslen=%lu\n",
				request.method.c_str(),
				response.status_code,
				request.ipstr.c_str(),
				request.target.c_str(),
				request.head.length(),
				request.body.length(),
				response.body.length()
			);

			return ERROR_CODE::SUCCESS;
		}
	};
}
