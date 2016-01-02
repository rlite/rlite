cmake_minimum_required(VERSION 2.8)

project(rinalite)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")

include_directories(${INCLUDE_DIR})

add_library(rinalite SHARED user/rina-utils.c user/rina-kernel-numtables.c user/rina-conf-numtables.c user/helpers.c user/evloop.c user/pending_queue.c user/application.c)

target_link_libraries(rinalite pthread)

add_executable(rinaperf user/rinaperf.c)
add_executable(uipcp-server user/uipcp.c user/uipcp-server.c)
add_executable(rina-config user/rina-config.c)

target_link_libraries(rinaperf rinalite)
target_link_libraries(uipcp-server rinalite)
target_link_libraries(rina-config rinalite)

install(TARGETS rinaperf uipcp-server rina-config DESTINATION usr/bin)
install(TARGETS rinalite DESTINATION usr/lib)
