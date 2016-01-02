find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})
find_package(PythonLibs)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_SWIG_FLAGS "")
swig_add_module(rlite python rlite.i ../utils.c ../ker-numtables.c ../conf-numtables.c ../ctrl.c)
swig_link_libraries(rlite ${PYTHON_LIBRARIES})

# Installation directives
#install(TARGETS rlite rlite-evloop rlite-cdap rlite-conf DESTINATION usr/lib)
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CDAP.pb.h DESTINATION usr/include/rlite)
