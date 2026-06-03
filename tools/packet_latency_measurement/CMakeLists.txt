cmake_minimum_required(VERSION 3.10)
project(PacketLatencyMeasurement)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.cpp
    ../common/network_utils.cpp
    ../common/packet_sender.cpp
    ../common/packet_receiver.cpp
)

# Header files (for IDE integration)
set(HEADERS
    ../common/packet_common.h
    ../common/network_utils.h
    ../common/packet_sender.h
    ../common/packet_receiver.h
)

add_executable(packet_latency_measurement ${SOURCES} ${HEADERS})

# Add cxxopts include directory (header-only library)
target_include_directories(packet_latency_measurement PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    external/cxxopts/include
)

# Link pthread library
find_package(Threads REQUIRED)
target_link_libraries(packet_latency_measurement Threads::Threads)

# Set compiler warnings
target_compile_options(packet_latency_measurement PRIVATE -Wall -Wextra)
