cmake_minimum_required(VERSION 3.15)
project(NetSpecter VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Find Dependencies
find_package(PkgConfig REQUIRED)
# This finds the headers and library for libbpf
pkg_check_modules(LIBBPF REQUIRED libbpf)
# Find libpcap
find_library(PCAP_LIB pcap REQUIRED)

# 2. Include Directories (include your local headers and BPF headers)
include_directories(include ${LIBBPF_INCLUDE_DIRS})

# 3. Collect all source files
# Note: file(GLOB) is fine for small projects, but manual lists are "BigBrain" 
# because CMake doesn't always see new files automatically with GLOB.
file(GLOB_RECURSE SOURCES "src/*.cpp")

# 4. Create Executable
add_executable(netspecter ${SOURCES})

# 5. Link everything together
# Added ${LIBBPF_LIBRARIES} to the link stage
target_link_libraries(netspecter 
    ${PCAP_LIB} 
    ${LIBBPF_LIBRARIES} 
    pthread
)