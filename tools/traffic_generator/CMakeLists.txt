cmake_minimum_required(VERSION 3.10)
project(TrafficGenerator)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.cpp
    ../common/network_utils.cpp
    ../common/packet_sender.cpp
)

# Header files (for IDE integration)
set(HEADERS
    ../common/packet_common.h
    ../common/network_utils.h
    ../common/packet_sender.h
)

add_executable(traffic_generator ${SOURCES} ${HEADERS})

# Add cxxopts include directory (header-only library)
target_include_directories(traffic_generator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    ../packet_latency_measurement/external/cxxopts/include
)

# Link pthread library
find_package(Threads REQUIRED)
target_link_libraries(traffic_generator Threads::Threads)

# Set compiler warnings
target_compile_options(traffic_generator PRIVATE -Wall -Wextra)
