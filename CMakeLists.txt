# Set the minimum version of CMake that can be used
# To find the cmake version run
# $ cmake --version
cmake_minimum_required(VERSION 3.12)

set (CMAKE_CXX_STANDARD 20)

# Default to an optimized build. Upstream's `cmake .. && make` leaves CMAKE_BUILD_TYPE empty, which
# compiles main.cpp (all of the online phase) at -O0 while libOTe itself is a Release build.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Set the project name
project (oprf)

# Add an executable
add_executable(oprf main.cpp)

find_package(libOTe 2.2.0 REQUIRED 
    COMPONENTS
        std_20
        
        Release

        boost
        sodium

        sse
        avx
        no_asan
        no_pic

        mr_kyber
        iknp
        kkrt
)

target_link_libraries(oprf oc::libOTe)


