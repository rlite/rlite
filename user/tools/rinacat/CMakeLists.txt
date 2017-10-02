# Executables
add_executable(rinacat rinacat.c)
target_link_libraries(rinacat rina-api)

 # Installation directives
install(TARGETS rinacat DESTINATION usr/bin)
