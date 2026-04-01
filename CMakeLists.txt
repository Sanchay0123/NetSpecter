cmake_minimum_required(VERSION 3.15)
project(NetSpecter VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libpcap
find_library(PCAP_LIB pcap)
include_directories(include)

# Collect all source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(netspecter ${SOURCES})

# Link pcap and threads (for our async capture)
target_link_libraries(netspecter ${PCAP_LIB} pthread)