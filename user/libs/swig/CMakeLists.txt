find_package(SWIG)
find_package(PythonLibs)

if (NOT SWIG_FOUND)
    message("SWIG not found: Python bindings will not be built")
elseif(NOT PYTHONLIBS_FOUND)
    message("Python not found: Python bindings will not be built")
else()
    include(${SWIG_USE_FILE})
    include_directories(${PYTHON_INCLUDE_PATH})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    # Global swig flags

    if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} VERSION_LESS 3.8)
        message("CMake version < 3.8: using legacy swig commands")
        set(CMAKE_SWIG_FLAGS "")
        swig_add_module(rina python rlite.i)
        set_source_files_properties(cdap.i PROPERTIES CPLUSPLUS ON)
        set_source_files_properties(cdap.i PROPERTIES SWIG_FLAGS "-c++")
        swig_add_module(cdap python cdap.i)
    else()
        swig_add_library(rina LANGUAGE python SOURCES rlite.i)
        set_property(SOURCE cdap.i PROPERTY CPLUSPLUS ON)
        swig_add_library(cdap LANGUAGE python SOURCES cdap.i)
    endif()

    # Tell the build system to link the _rina.so python module against
    # the librina-api.so library
    swig_link_libraries(rina ${PYTHON_LIBRARIES} rina-api)

    # Tell the build system to link the _cdap.so python module against
    # the librina-api.so library
    swig_link_libraries(cdap ${PYTHON_LIBRARIES} cdap)

    # Installation directives
    execute_process(COMMAND python -c "from distutils import sysconfig; print(sysconfig.get_python_lib(plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}'))"
                    OUTPUT_VARIABLE _ABS_PYTHON_MODULE_PATH
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    get_filename_component(_ABS_PYTHON_MODULE_PATH ${_ABS_PYTHON_MODULE_PATH} ABSOLUTE)
    file(RELATIVE_PATH _REL_PYTHON_MODULE_PATH ${CMAKE_INSTALL_PREFIX} ${_ABS_PYTHON_MODULE_PATH})
    set(PYTHON_MODULE_PATH ${_REL_PYTHON_MODULE_PATH})
    string(REGEX REPLACE "^lib" "usr/lib" PYTHON_MODULE_PATH ${PYTHON_MODULE_PATH})
    message("PYTHON_MODULE_PATH = ${PYTHON_MODULE_PATH}")

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_rina_REAL_NAME}.so DESTINATION ${PYTHON_MODULE_PATH})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rina.py DESTINATION ${PYTHON_MODULE_PATH})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_cdap_REAL_NAME}.so DESTINATION ${PYTHON_MODULE_PATH})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cdap.py DESTINATION ${PYTHON_MODULE_PATH})
endif()
