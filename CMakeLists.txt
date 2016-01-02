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

file(GLOB RLITE_HEADERS "include/rlite/*.h")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")
message(STATUS "RLITE HEADERS: ${RLITE_HEADERS}")

add_definitions("-Wall")

include_directories(${INCLUDE_DIR})

install(FILES ${RLITE_HEADERS} DESTINATION usr/include/rlite)
install(FILES include/rlite/cdap.hpp DESTINATION usr/include/rlite)

add_subdirectory(user)
