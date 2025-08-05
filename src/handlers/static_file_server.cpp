#include <cstdlib>
#include <filesystem>
#include <string>
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"
#include "../HTTPServer.cpp"
#include "../utils/file_io.cpp"
#include "src/utils/config_util.cpp"

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

		static static_file_server_config from_config(std::map<string, string> pairs) {
			static_file_server_config config;
			if(pairs.contains("prefix")) config.prefix = utils::config_util::parse_string(pairs.at("prefix"));
			if(pairs.contains("can_get_files")) config.can_get_files = utils::config_util::parse_bool(pairs.at("can_get_files"));
			if(pairs.contains("can_put_files")) config.can_put_files = utils::config_util::parse_bool(pairs.at("can_put_files"));
			if(pairs.contains("can_delete_files")) config.can_delete_files = utils::config_util::parse_bool(pairs.at("can_delete_files"));
			return config;
		}
	};

	struct static_file_server_struct {
		static_file_server_config config;
		path prefix_canonical;

		static_file_server_struct(static_file_server_config config) {
			this->config = config;
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

		http_response& return_status(http_response& response, const int status) {
			response.status_code = status;
			return response;
		}

		http_response handle_request(const http_request& request) {
			http_response response;

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
				return return_status(response, 500);
			}
			bool is_within_directory =
				target_canonical.string().starts_with(prefix_canonical.string()) &&
				target_canonical.string().length() > prefix_canonical.string().length();
			if(!is_within_directory) {
				fprintf(stderr, "[SECURITY] target is not within prefix directory!\n\tprefix=%s\n\ttarget=%s\n", prefix_canonical.c_str(), target_canonical.c_str());
				return return_status(response, 404);
			}
			target = target_canonical;

			// ============================================================
			// request methods.
			// ------------------------------------------------------------

			const bool method_get = request.method == HTTP::METHODS::GET;
			const bool method_head = request.method == HTTP::METHODS::HEAD;
			if(method_get || method_head) {
				if(!config.can_get_files) return return_status(response, 403);
				bool can_read_file = fs::exists(target) && fs::is_regular_file(target);
				if(!can_read_file) return return_status(response, 404);
				int status;
				const string content = fio::read_file(target, status);
				if(status != 0) return return_status(response, 500);
				string ext = target.extension();
				response.headers[HTTP::HEADERS::content_type] = get_mime_type(ext);
				response.headers[HTTP::HEADERS::content_length] = int_to_string(content.length());
				if(method_get) response.body = content;
				return return_status(response, 200);
			}

			if(request.method == HTTP::METHODS::PUT) {
				if(!config.can_put_files) return return_status(response, 403);
				const bool can_write_file = fs::is_directory(target.parent_path()) && (!fs::exists(target) || fs::is_regular_file(target));
				if(!can_write_file) return return_status(response, 405);
				int status;
				bool file_exists = fs::is_regular_file(target);
				fio::write_file(target, status, request.body.data(), request.body.size());
				return return_status(response, (status != 0) ? 500 : (file_exists ? 204 : 201));
			}

			if(request.method == HTTP::METHODS::DELETE) {
				if(!config.can_delete_files) return return_status(response, 403);
				const bool can_delete_file = fs::exists(target) && fs::is_regular_file(target);
				if(!can_delete_file) return return_status(response, 404);
				int status;
				fio::delete_file(target, status);
				return return_status(response, (status != 0) ? 500 : 204);
			}

			return return_status(response, 501);
		}

	};

	// example server.
	struct HTTPFileServer : HTTP::HTTPServer {
		static_file_server_struct sfs;

		HTTPFileServer(const char* hostname, const char* portname, static_file_server_config config) : HTTPServer(hostname, portname), sfs(config) {}

		http_response handle_request(const accept_connection_struct& connection, const http_request& request) override {
			return sfs.handle_request(request);
		}
	};
}
