build:
g++ -std=c++23 -o ./bin/main_server.elf ./src/main_server.cpp
g++ -std=c++23 -o ./bin/main_client.elf ./src/main_client.cpp

run:
./bin/main_server.elf 3490
./bin/main_client.elf 3490
