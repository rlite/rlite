# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-echo-bin rina-echo.c)
add_executable(rlite-ctl rlite-ctl.c)
add_executable(rina-gw rina-gw.cpp)

target_link_libraries(rinaperf rlite)
target_link_libraries(rina-echo-bin rlite)
target_link_libraries(rlite-ctl rlite rlite-conf)
target_link_libraries(rina-gw rlite rlite-evloop ${CMAKE_THREAD_LIBS_INIT})

 # Installation directives
install(TARGETS rinaperf rlite-ctl rina-gw rina-echo-bin DESTINATION usr/bin)
install(FILES rina-gw.conf DESTINATION etc/rlite)
install(PROGRAMS inet-echo rina-echo DESTINATION usr/bin)
