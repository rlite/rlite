cmake_minimum_required(VERSION 3.1)

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

set(CMAKE_CXX_STANDARD 11)

# Some globbing and headers include
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB RLITE_HEADERS "include/rlite/*.h")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")
message(STATUS "RLITE HEADERS: ${RLITE_HEADERS}")

add_definitions("-Wall -g")
if(DEBUG STREQUAL "y")
    add_definitions("-DRL_DEBUG")
    message(STATUS "Configuring for debug mode")
endif()

include_directories(${INCLUDE_DIR})

install(FILES ${RLITE_HEADERS} DESTINATION usr/include/rlite)
install(FILES include/rina/cdap.hpp DESTINATION usr/include/rina)
install(FILES "include/rina/api.h" DESTINATION usr/include/rina)

add_subdirectory(user)
add_subdirectory(tests)
