# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oesignext main.c)

target_link_libraries(oesignext oehost)

# assemble into proper collector dir
set_property(TARGET oesignext PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oesignext EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
