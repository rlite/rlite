# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-rr-tool rina-rr-tool.c)
add_executable(rlite-config rlite-config.c)
add_executable(rina-gw rina-gw.cpp)

target_link_libraries(rinaperf rlite)
target_link_libraries(rina-rr-tool rlite)
target_link_libraries(rlite-config rlite rlite-conf)
target_link_libraries(rina-gw rlite rlite-evloop ${CMAKE_THREAD_LIBS_INIT})

 # Installation directives
install(TARGETS rinaperf rlite-config rina-gw rina-rr-tool DESTINATION usr/bin)
install(FILES rina-gw.conf DESTINATION etc/rlite)
install(PROGRAMS inet-rr-tool DESTINATION usr/bin)
