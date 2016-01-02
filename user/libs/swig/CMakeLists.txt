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
    set(CMAKE_SWIG_FLAGS "")

    swig_add_module(rlite python rlite.i)

    set_source_files_properties(cdap.i PROPERTIES CPLUSPLUS ON)
    set_source_files_properties(cdap.i PROPERTIES SWIG_FLAGS "-c++")
    swig_add_module(rlite_cdap python cdap.i)

    # Tell the build system to link the _rlite.so python module against
    # the librlite.so library
    swig_link_libraries(rlite ${PYTHON_LIBRARIES} rlite)

    # Tell the build system to link the _rlite_cdap.so python module against
    # the librlite.so library
    swig_link_libraries(rlite_cdap ${PYTHON_LIBRARIES} rlite-cdap)

    # Installation directives
    execute_process(COMMAND python -c "from distutils import sysconfig; print(sysconfig.get_python_lib(plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}'))"
                    OUTPUT_VARIABLE _ABS_PYTHON_MODULE_PATH
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    get_filename_component(_ABS_PYTHON_MODULE_PATH ${_ABS_PYTHON_MODULE_PATH} ABSOLUTE)
    file(RELATIVE_PATH _REL_PYTHON_MODULE_PATH ${CMAKE_INSTALL_PREFIX} ${_ABS_PYTHON_MODULE_PATH})
    set(PYTHON_MODULE_PATH ${_REL_PYTHON_MODULE_PATH})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_rlite_REAL_NAME}.so DESTINATION ${PYTHON_MODULE_PATH})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rlite.py DESTINATION ${PYTHON_MODULE_PATH})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_rlite_cdap_REAL_NAME}.so DESTINATION ${PYTHON_MODULE_PATH})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rlite_cdap.py DESTINATION ${PYTHON_MODULE_PATH})
endif()
