# SPDX-License-Identifier: GPL-3.0-only
# GUI: controller and view in C (GTK4 + libadwaita).
# libadwaita 1.5 for AdwDialog; the shortcuts dialog uses 1.8 when available.
pkg_check_modules(ADWAITA REQUIRED IMPORTED_TARGET gtk4 libadwaita-1>=1.5)

# Icons used inside the app, compiled in (data/gaudit.gresource.xml).
find_program(GLIB_COMPILE_RESOURCES glib-compile-resources REQUIRED)
set(GAUDIT_RESOURCE_XML ${PROJECT_SOURCE_DIR}/data/gaudit.gresource.xml)
execute_process(COMMAND ${GLIB_COMPILE_RESOURCES} --generate-dependencies
                        --sourcedir ${PROJECT_SOURCE_DIR}/data ${GAUDIT_RESOURCE_XML}
                OUTPUT_VARIABLE GAUDIT_RESOURCE_DEPS OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE "\n" ";" GAUDIT_RESOURCE_DEPS "${GAUDIT_RESOURCE_DEPS}")
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gaudit-resources.c
  COMMAND ${GLIB_COMPILE_RESOURCES} --generate-source --sourcedir ${PROJECT_SOURCE_DIR}/data
          --target ${CMAKE_CURRENT_BINARY_DIR}/gaudit-resources.c ${GAUDIT_RESOURCE_XML}
  DEPENDS ${GAUDIT_RESOURCE_XML} ${GAUDIT_RESOURCE_DEPS}
  VERBATIM)

add_executable(gaudit
  ${CMAKE_CURRENT_BINARY_DIR}/gaudit-resources.c
  main.c
  gaudit-app.c
  gaudit-orchestrator.c
  gaudit-run-page.c
  gaudit-firewall-text.c
  gaudit-category.c
  gaudit-sourceless-page.c
  gaudit-session.c
  gaudit-window.c
  gaudit-task.c
  gaudit-task-page.c
)
target_link_libraries(gaudit PRIVATE PkgConfig::ADWAITA gaudit_model gaudit_backend gaudit_probe gaudit_config)
install(TARGETS gaudit RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
