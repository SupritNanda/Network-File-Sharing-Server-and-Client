# Makefile for Network File Sharing Project

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LDFLAGS = -pthread

# Targets
all: server client

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server

client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client

# Phony targets
.PHONY: all clean

clean:
	rm -f server client