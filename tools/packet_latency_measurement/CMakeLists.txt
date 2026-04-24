cmake_minimum_required(VERSION 3.10)
project(PacketLatencyMeasurement)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(packet_latency_measurement packet_latency_measurement.cpp)

# Add cxxopts include directory (header-only library)
target_include_directories(packet_latency_measurement PRIVATE external/cxxopts/include)

# Link pthread library
find_package(Threads REQUIRED)
target_link_libraries(packet_latency_measurement Threads::Threads)

# Set compiler warnings
target_compile_options(packet_latency_measurement PRIVATE -Wall -Wextra)
