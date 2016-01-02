cmake_minimum_required(VERSION 2.8)

project(rinalite)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB RINA_HEADERS "include/rina/*.h")

message(STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "INCLUDE_DIR: ${INCLUDE_DIR}")
message(STATUS "RINA HEADERS: ${RINA_HEADERS}")

include_directories(${INCLUDE_DIR})

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(CDAP_GPB_SRC CDAP_GPB_HDR user/CDAP.proto)

add_library(rinalite SHARED user/rinalite-utils.c user/rina-kernel-numtables.c user/rina-conf-numtables.c user/rinalite-evloop.c user/pending_queue.c user/rinalite-appl.c)
add_library(rinalite-cdap SHARED user/cdap.cpp ${CDAP_GPB_SRC} ${CDAP_GPB_HDR})
add_library(uipcp-rib STATIC user/uipcp-rib.cpp)

target_link_libraries(rinalite pthread)
target_link_libraries(rinalite-cdap rinalite ${PROTOBUF_LIBRARY})

message(STATUS "Adding include dir ${CMAKE_CURRENT_BINARY_DIR} to rinalite-cdap target")
target_include_directories(rinalite-cdap PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_executable(rinaperf user/rinaperf.c)
add_executable(rinalite-uipcps user/uipcp-container.c user/uipcp-unix.c)
add_executable(rina-config user/rina-config.c)
add_executable(test-cdap user/test-cdap.cpp)

target_link_libraries(rinaperf rinalite)
target_link_libraries(rinalite-uipcps rinalite uipcp-rib)
target_link_libraries(rina-config rinalite)
target_link_libraries(test-cdap rinalite-cdap)

install(TARGETS rinaperf rinalite-uipcps rina-config DESTINATION usr/bin)
install(TARGETS rinalite DESTINATION usr/lib)
install(FILES ${RINA_HEADERS} DESTINATION include/rina)
