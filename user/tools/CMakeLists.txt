# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-rr-tool-bin rina-rr-tool.c)
add_executable(rlite-ctl rlite-ctl.c)
add_executable(rina-gw rina-gw.cpp)

target_link_libraries(rinaperf rlite)
target_link_libraries(rina-rr-tool-bin rlite)
target_link_libraries(rlite-ctl rlite rlite-conf)
target_link_libraries(rina-gw rlite rlite-evloop ${CMAKE_THREAD_LIBS_INIT})

 # Installation directives
install(TARGETS rinaperf rlite-ctl rina-gw rina-rr-tool-bin DESTINATION usr/bin)
install(FILES rina-gw.conf DESTINATION etc/rlite)
install(PROGRAMS inet-rr-tool rina-rr-tool DESTINATION usr/bin)
