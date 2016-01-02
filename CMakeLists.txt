cmake_minimum_required(VERSION 2.8)

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

# Some globbing and headers include
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB RINA_HEADERS "include/rlite/*.h")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")
message(STATUS "RINA HEADERS: ${RINA_HEADERS}")

add_definitions("-Wall")

include_directories(${INCLUDE_DIR})

add_subdirectory(user)

install(FILES ${RINA_HEADERS} DESTINATION usr/include/rlite)
