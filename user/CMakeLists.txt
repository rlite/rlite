# External dependencies
find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)

if(PROTOBUF_PROTOC_EXECUTABLE STREQUAL "PROTOBUF_PROTOC_EXECUTABLE-NOTFOUND")
	message(FATAL_ERROR "Cannot find protocol buffer compiler")
endif()

add_subdirectory(libs)
add_subdirectory(tools)
add_subdirectory(uipcps)
