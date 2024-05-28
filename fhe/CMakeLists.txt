cmake_minimum_required(VERSION 3.26)
project(fhe)

file(COPY assets DESTINATION ${CMAKE_BINARY_DIR})
set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

find_package(OpenFHE REQUIRED PATHS "${CMAKE_SOURCE_DIR}/assets/dependencies/openfhe")
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif ()

#set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )
message(STATUS ${OpenFHE_LIBDIR})
include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )

message(STATUS "${OpenFHE_EXE_LINKER_FLAGS}")
set( CMAKE_EXE_LINKER_FLAGS "-static")
#link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
link_libraries(OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static)

# Executable to test network evaluation
add_executable(fhe main.cpp
        lib/src/neural_net_io.cpp
        lib/include/neural_net.h
        lib/src/neural_net_func.cpp
        lib/include/neural_net_evaluator.h
        lib/include/typedefs.h
        lib/src/neural_net_evaluator.cpp)

target_include_directories(fhe PUBLIC lib/include)
target_include_directories(fhe PUBLIC assets/dependencies/nlohmann-json)

# Executable that runs network from stored key material and ciphertexts
add_executable(fhe_server run_network_server.cpp
        lib/src/neural_net_io.cpp
        lib/include/neural_net.h
        lib/src/neural_net_func.cpp
        lib/include/neural_net_evaluator.h
        lib/include/typedefs.h
        lib/src/neural_net_evaluator.cpp)
target_include_directories(fhe_server PUBLIC lib/include)
target_include_directories(fhe_server PUBLIC assets/dependencies/nlohmann-json)

# Executable that generates the crypto configuration file and keys
add_executable(client_keygen setup_client.cpp
        lib/src/neural_net_io.cpp
        lib/include/neural_net.h
        lib/src/neural_net_func.cpp
        lib/include/neural_net_evaluator.h
        lib/include/typedefs.h
        lib/src/neural_net_evaluator.cpp)
target_include_directories(client_keygen PUBLIC lib/include)
target_include_directories(client_keygen PUBLIC assets/dependencies/nlohmann-json)

# Executable that encrypts a sample using the public key
add_executable(iot_protect iot_protect.cpp lib/src/neural_net_io.cpp
        lib/include/neural_net.h
        lib/src/neural_net_func.cpp
        lib/include/neural_net_evaluator.h
        lib/include/typedefs.h
        lib/src/neural_net_evaluator.cpp)
target_include_directories(iot_protect PUBLIC lib/include)
target_include_directories(iot_protect PUBLIC assets/dependencies/nlohmann-json)
add_executable(test_deser test_deserial.cpp)
