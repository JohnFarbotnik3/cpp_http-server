#include <array>
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <system_error>

/*
	the purpose of this class is to serialize data
	in a way that makes it easy to communicate with a web browser.

	in particular, these functions need to be easy to re-write in javascript.

	NOTE: for better performance, compiling these functions to webassembly
	is also an option, however I'm not entirely sure if network-to-host style
	conversions will behave well (different versions may have to be compiled).
*/
namespace serialization {

	struct Serializer {
		char* data;
		int capacity;
		int position;

		Serializer(int capacity=64) {
			this->data = new char[capacity];
			this->capacity = capacity;
			this->position = 0;
		}

		~Serializer() {
			delete[] this->data;
		}

		void reserve(int space) {
			if(space > capacity - position) {
				int new_cap = (capacity * 3 / 2) + space;
				char* new_data = new char[new_cap];
				memcpy(new_data, data, capacity);
				delete[] data;
				data = new_data;
				capacity = new_cap;
			}
		}

		void reset() {
			position = 0;
		}

		// return pointer to current position in data, then advance.
		char* advance(size_t n) {
			char* ptr = data + position;
			position += n;
			return ptr;
		}

		void write(char c) {
			data[position++] = c;
		}
		char read() {
			return data[position++];
		}

		void write(const char* src, size_t len) {
			memcpy(data + position, src, len);
			position += len;
		}
		void read(char* dst, size_t len) {
			memcpy(dst, data + position, len);
			position += len;
		}
	};


	void		encode_u32(Serializer& buf, uint32_t value) {
		buf.reserve(4);
		uint8_t* ptr = (uint8_t*) buf.advance(4);
		ptr[0] = (value >> 8*0) & 0xff;
		ptr[1] = (value >> 8*1) & 0xff;
		ptr[2] = (value >> 8*2) & 0xff;
		ptr[3] = (value >> 8*3) & 0xff;
	}
	uint32_t	decode_u32(Serializer& buf) {
		uint8_t* ptr = (uint8_t*) buf.advance(4);
		uint32_t value = (
			(ptr[0] << 8*0) |
			(ptr[1] << 8*1) |
			(ptr[2] << 8*2) |
			(ptr[3] << 8*3)
		);
		return value;
	}


	template<typename T>
	void	encode_fp(Serializer& buf, T value) {
		std::array<char, 64> str;
		auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value);
		if (ec == std::errc()) {
			uint8_t len = ptr - str.data();
			buf.reserve(len + 1);
			buf.write(len);
			buf.write(str.data(), len);
		} else {
			printf("error: %s\n", std::make_error_code(ec).message().c_str());
		}
	}
	template<typename T>
	T	decode_fp(Serializer& buf) {
		uint8_t len = buf.read();
		char* str = buf.advance(len);
		T value;
		std::from_chars(str, str + len, value);
		return value;
	}
	void	encode_f32(Serializer& buf, float value) {
		return encode_fp<float>(buf, value);
	}
	void	encode_f64(Serializer& buf, double value) {
		return encode_fp<double>(buf, value);
	}
	float	decode_f32(Serializer& buf) {
		return decode_fp<float>(buf);
	}
	double	decode_f64(Serializer& buf) {
		return decode_fp<double>(buf);
	}


	void		encode_string(Serializer& buf, const std::string& str) {
		buf.reserve(str.length() + 4);
		encode_u32(buf, str.length());
		buf.write(str.data(), str.length());
	}
	std::string	decode_string(Serializer& buf) {
		int length = decode_u32(buf);
		std::string str;
		str.resize(length);
		buf.read(str.data(), length);
		return str;
	}


	void test() {
		uint32_t	u32_in = 1234567890;
		float		f32_in = 3.1415926535897932384626;
		double		f64_in = 3.1415926535897932384626;
		std::string	str_in = "abc 123 :) 111222333444555666777888999000";
		printf("in u32: %u\n", u32_in);
		printf("in f32: %.20f\n", f32_in);
		printf("in f64: %.20f\n", f64_in);
		printf("in str: %s\n", str_in.c_str());

		Serializer buf(32);
		encode_u32(buf, u32_in);
		encode_f32(buf, f32_in);
		encode_f64(buf, f64_in);
		encode_string(buf, str_in);
		printf("string_view:\n%s\n", std::string_view(buf.data, buf.data+buf.position).data());

		buf.reset();
		uint32_t	u32_out = decode_u32(buf);
		float		f32_out = decode_f32(buf);
		double		f64_out = decode_f64(buf);
		std::string	str_out = decode_string(buf);
		printf("out u32: %u\n", u32_out);
		printf("out f32: %.20f\n", f32_out);
		printf("out f64: %.20f\n", f64_out);
		printf("out str: %s\n", str_out.c_str());

		assert(u32_in == u32_out);
		assert(f32_in == f32_out);
		assert(f64_in == f64_out);
		assert(str_in == str_out);
	}
}
