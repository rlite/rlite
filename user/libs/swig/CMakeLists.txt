find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})
find_package(PythonLibs)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_SWIG_FLAGS "")
swig_add_module(rlite python rlite.i)
swig_link_libraries(rlite ${PYTHON_LIBRARIES} rlite)

# Installation directives
#install(TARGETS _rlite DESTINATION usr/lib ${PYTHON_SITE_PACKAGES})
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rlite.py DESTINATION ${PYTHON_SITE_PACKAGES})
