# Executables
add_executable(rinaperf rinaperf.c)
add_executable(rina-config rina-config.c)

target_link_libraries(rinaperf rlite)
target_link_libraries(rina-config rlite rlite-conf)

 # Installation directives
install(TARGETS rinaperf rina-config DESTINATION usr/bin)

