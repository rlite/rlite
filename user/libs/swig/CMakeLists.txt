find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})
find_package(PythonLibs)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_SWIG_FLAGS "")
swig_add_module(rlite python rlite.i)
# Tell the build system to link the _rlite.so python module against
# the librlite.so library
swig_link_libraries(rlite ${PYTHON_LIBRARIES} rlite)

# Installation directives
execute_process(COMMAND python -c "from distutils import sysconfig; print(sysconfig.get_python_lib(plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}'))"
                OUTPUT_VARIABLE _ABS_PYTHON_MODULE_PATH
                OUTPUT_STRIP_TRAILING_WHITESPACE)
get_filename_component(_ABS_PYTHON_MODULE_PATH ${_ABS_PYTHON_MODULE_PATH} ABSOLUTE)
file(RELATIVE_PATH _REL_PYTHON_MODULE_PATH ${CMAKE_INSTALL_PREFIX} ${_ABS_PYTHON_MODULE_PATH})
set(PYTHON_MODULE_PATH ${_REL_PYTHON_MODULE_PATH})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_rlite_REAL_NAME}.so DESTINATION ${PYTHON_MODULE_PATH})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rlite.py DESTINATION ${PYTHON_MODULE_PATH})
