cmake_minimum_required(VERSION 3.27)
project(fhe)

file(COPY assets DESTINATION ${CMAKE_BINARY_DIR})
set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

add_executable(fhe main.cpp
        lib/src/neural_net_io.cpp
        lib/include/neural_net.h
        lib/src/neural_net_func.cpp)

target_include_directories(fhe PUBLIC lib/include)
target_include_directories(fhe PUBLIC assets/dependencies/nlohmann-json)
