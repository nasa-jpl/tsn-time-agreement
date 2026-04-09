cmake_minimum_required(VERSION 3.10)
project(RawPacketTest)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# On macOS, ensure we can find C++ standard library headers
if(APPLE)
    execute_process(COMMAND xcrun --show-sdk-path
                    OUTPUT_VARIABLE OSX_SDK_PATH
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isysroot ${OSX_SDK_PATH} -I${OSX_SDK_PATH}/usr/include/c++/v1")
endif()

add_executable(raw_packet_test raw_packet_test.cpp)

# Link pthread library
find_package(Threads REQUIRED)
target_link_libraries(raw_packet_test Threads::Threads)

# Set compiler warnings
target_compile_options(raw_packet_test PRIVATE -Wall -Wextra)
