option(MAC2IFNAME, "Include mac2ifname binary tool" OFF)

# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-echo-async rina-echo-async.c)
add_executable(rlite-ctl rlite-ctl.c)
add_executable(rina-gw rina-gw.cpp)
add_executable(iporinad iporinad.cpp)
if (MAC2IFNAME)
add_executable(mac2ifname mac2ifname.c)
endif()

target_link_libraries(rinaperf rina-api ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(rina-echo-async rina-api)
target_link_libraries(rlite-ctl rina-api rlite-conf)
target_link_libraries(rina-gw rina-api ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(iporinad rina-api ${CMAKE_THREAD_LIBS_INIT})

 # Installation directives
install(TARGETS rinaperf rlite-ctl rina-gw rina-echo-async DESTINATION usr/bin)
if (MAC2IFNAME)
install(TARGETS mac2ifname DESTINATION usr/bin)
endif()
install(FILES rina-gw.conf DESTINATION etc/rlite)
install(PROGRAMS inet-toy rina-toy DESTINATION usr/bin)
