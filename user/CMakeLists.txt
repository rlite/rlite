# External dependencies
find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)

if(PROTOBUF_PROTOC_EXECUTABLE STREQUAL "PROTOBUF_PROTOC_EXECUTABLE-NOTFOUND")
	message(FATAL_ERROR "Cannot find protocol buffer compiler")
endif()

if(${Protobuf_VERSION} VERSION_GREATER_EQUAL "3.4.0")
	add_definitions("-DHAVE_GPB_BYTE_SIZE_LONG")
endif()
message(STATUS "PROTOBUF VERSION ${Protobuf_VERSION}")

add_subdirectory(libs)
add_subdirectory(tools)
add_subdirectory(uipcps)
