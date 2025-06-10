# https://unix.stackexchange.com/questions/309254/g-how-to-use-std-c14-be-default
# https://stackoverflow.com/questions/2481269/how-to-make-a-simple-c-makefile
# https://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/

# TODO: figure out how to specify the following directories: bin, build, src.

CC=gcc
CXX=g++
CPPFLAGS=-std=c++23
LDFLAGS=
LDLIBS=

main: main.o
	g++ $(LDFLAGS) -o main main.o $(LDLIBS)

main.o: main.cpp test_sockets.cpp types.cpp
	g++ $(CPPFLAGS) -c main.cpp

server_http: server_http.o
	g++ $(LDFLAGS) -o server_http server_http.o $(LDLIBS)

server_http.o: server_http.cpp types.cpp
	g++ $(CPPFLAGS) -c server_http.cpp
