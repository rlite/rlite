# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-config rina-config.c)
add_executable(rina-gw rina-gw.cpp)

target_link_libraries(rinaperf rlite)
target_link_libraries(rina-config rlite rlite-conf)
target_link_libraries(rina-gw rlite ${CMAKE_THREAD_LIBS_INIT})

 # Installation directives
install(TARGETS rinaperf rina-config rina-gw DESTINATION usr/bin)
install(FILES rina-gw.conf DESTINATION etc/rlite)
