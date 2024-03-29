cmake_minimum_required(VERSION 3.5)

project(rlite)

# Compiler checks
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")

if(CMAKE_C_COMPILER STREQUAL "CMAKE_C_COMPILER-NOTFOUND")
    message(FATAL_ERROR "Cannot find C compiler")
endif()

if(CMAKE_CXX_COMPILER STREQUAL "CMAKE_CXX_COMPILER-NOTFOUND")
    message(FATAL_ERROR "Cannot find C++ compiler")
endif()

# Prepare compiler flags for C++17
set(CMAKE_CXX_STANDARD 17)

# Some globbing and headers include
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB RLITE_HEADERS "include/rlite/*.h")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")
message(STATUS "RLITE HEADERS: ${RLITE_HEADERS}")

add_definitions("-Wall -g -Werror")
if(DEBUG STREQUAL "y")
    add_definitions("-DRL_DEBUG")
    # Enable address sanitizer
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    message(STATUS "Configuring for debug mode")
elseif(OPTIMIZE STREQUAL "y")
    add_definitions("-O2")
    message(STATUS "Building with optimization enabled (-O2)")
endif()

include_directories(${INCLUDE_DIR})

install(FILES ${RLITE_HEADERS} DESTINATION usr/include/rlite)
install(FILES include/rina/cdap.hpp DESTINATION usr/include/rina)
install(FILES "include/rina/api.h" DESTINATION usr/include/rina)
file(GLOB BASH_COMPLETION_FILES "scripts/bash_completion/*")
install(FILES ${BASH_COMPLETION_FILES} DESTINATION etc/bash_completion.d)

enable_testing()

add_subdirectory(user)
add_subdirectory(tests)

# Support for generating deb, tar.gz, rpm, etc.
# The CPACK_GENERATOR value is actually overridden by the cpack -G option.
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 9)
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "gcc g++")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Vincenzo Maffione")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
SET(CPACK_SET_DESTDIR "ON")
set(CPACK_PACKAGE_DESCRIPTION "Recursive Inter-Network Architecture implementation")
include(CPack)
