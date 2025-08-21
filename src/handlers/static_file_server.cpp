#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"
#include "../HTTPServer.cpp"
#include "src/utils/config_util.cpp"
#include "src/http_util.cpp"

/*
https://man7.org/linux/man-pages/man2/pwrite.2.html
https://man7.org/linux/man-pages/man2/read.2.html
https://man7.org/linux/man-pages/man2/open.2.html
https://man7.org/linux/man-pages/man2/close.2.html
NOTE: pread/pwrite allows multiple threads to use the same file-descriptor

https://stackoverflow.com/questions/73601293/thread-safe-file-updates
*/
namespace HTTP::Handlers::static_file_server {
	using std::string;
	namespace fs = std::filesystem;


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
		fs::path prefix_canonical;

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

		void return_status(http_response& response, const int status_code) {
			response.status_code = status_code;
		}

		void handle_GET(const http_request& request, http_response& response, MessageBuffer& body_buffer, const fs::path path, const bool do_get) {
			if(!config.can_get_files) return return_status(response, 403);
			bool can_read_file = fs::exists(path) && fs::is_regular_file(path);
			if(!can_read_file) return return_status(response, 404);

			std::error_code ec;
			uintmax_t file_size = fs::file_size(path, ec);
			if(ec) {
				fprintf(stderr, "[handle_GET] failed to get file-size: %s [%s]\n", ec.message().c_str(), path.c_str());
				return_status(response, 500);
			}

			// TODO - range request support.
			size_t offset = 0;
			size_t count = file_size;// TODO - limit max count to prevent memory allocation DOS.
			if(offset > file_size) offset = file_size;
			if(count > file_size) count = std::min(count, file_size - offset);

			ssize_t n_read;
			if(do_get) {
				int fd = open(path.c_str(), O_RDONLY);
				if(fd == -1) {
					fprintf(stderr, "[handle_GET] failed to open file: %s [%s]\n", strerror(errno), path.c_str());
					return_status(response, 404);
				}

				body_buffer.reserve(count);
				n_read = pread(fd, body_buffer.data, count, offset);
				close(fd);

				if(n_read == -1) {
					fprintf(stderr, "[handle_GET] failed to read file: %s [%s]\n", strerror(errno), path.c_str());
					return_status(response, 500);
				} else {
					body_buffer.length = n_read;
				}
			} else {
				n_read = count;
			}

			response.headers[HTTP::HEADERS::content_type] = get_mime_type(path.extension());
			response.headers[HTTP::HEADERS::content_length] = int_to_string(n_read);
			return return_status(response, 200);
		}

		void handle_PUT(const http_request& request, http_response& response, MessageBuffer& body_buffer, const fs::path path) {
			if(!config.can_put_files) return return_status(response, 403);
			const bool can_write_file = fs::is_directory(path.parent_path()) && (!fs::exists(path) || fs::is_regular_file(path));
			if(!can_write_file) return return_status(response, 405);

			int status;
			bool file_exists = fs::is_regular_file(path);

			// TODO - range request support.
			size_t offset = 0;// TODO - limit offset to prevent sparse-file allocation DOS.
			size_t count = request.body.size();

			int fd = open(path.c_str(), O_WRONLY | O_CREAT);
			if(fd == -1) {
				fprintf(stderr, "[handle_PUT] failed to open file: %s [%s]\n", strerror(errno), path.c_str());
				return_status(response, 404);
			}

			ssize_t n_write = pwrite(fd, body_buffer.data, count, offset);
			close(fd);

			if(n_write == -1) {
				fprintf(stderr, "[handle_PUT] failed to write file: %s [%s]\n", strerror(errno), path.c_str());
				return_status(response, 500);
			}

			return return_status(response, file_exists ? 204 : 201);
		}

		void handle_DELETE(const http_request& request, http_response& response, MessageBuffer& body_buffer, const fs::path path) {
			if(!config.can_delete_files) return return_status(response, 403);
			const bool can_delete_file = fs::exists(path) && fs::is_regular_file(path);
			if(!can_delete_file) return return_status(response, 404);

			std::error_code ec;
			bool success = fs::remove(path, ec);
			if(!success) {
				fprintf(stderr, "[handle_DELETE] failed to delete file: %s [%s]\n", ec.message().c_str(), path.c_str());
				return return_status(response, 500);
			} else {
				return return_status(response, 204);
			}
		}

		void handle_request(const HTTPConnection& connection, const http_request& request, http_response& response, MessageBuffer& body_buffer) {
			response.clear();
			body_buffer.clear();

			response.protocol = HTTP_PROTOCOL_1_1;
			response.headers[HTTP::HEADERS::content_length] = "0";

			// modify target file path.
			fs::path target;
			if(request.path == "/") {
				target = fs::path(prefix_canonical / "index.html");
			} else {
				string str = request.path;
				if(str.starts_with("/")) str = str.substr(1);
				target = fs::path(prefix_canonical / str);
			}

			// SECURITY: ensure target file is both valid and within prefix directory.
			std::error_code ec;
			fs::path target_canonical = fs::weakly_canonical(target, ec);
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

			// request methods.
			if(request.method == HTTP::METHODS::GET		) return handle_GET(request, response, body_buffer, target, true);
			if(request.method == HTTP::METHODS::HEAD	) return handle_GET(request, response, body_buffer, target, false);
			if(request.method == HTTP::METHODS::PUT		) return handle_PUT(request, response, body_buffer, target);
			if(request.method == HTTP::METHODS::DELETE	) return handle_DELETE(request, response, body_buffer, target);
			return return_status(response, 501);
		}

	};

	// example server.
	struct HTTPFileServer : HTTP::HTTPServer {
		static_file_server_struct sfs;

		HTTPFileServer(const string hostname, const string portname, const int n_worker_threads, static_file_server_config config) : HTTPServer(hostname, portname, n_worker_threads), sfs(config) {}

		void handle_request(const HTTPConnection& connection, const http_request& request, http_response& response, MessageBuffer& body_buffer) override {
			return sfs.handle_request(connection, request, response, body_buffer);
		}
	};
}
