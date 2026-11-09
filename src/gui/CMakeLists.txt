# SPDX-License-Identifier: GPL-3.0-only
# GUI: controller and view in C (GTK4 + libadwaita).
pkg_check_modules(ADWAITA REQUIRED IMPORTED_TARGET gtk4 libadwaita-1>=1.4)

add_executable(gaudit
  main.c
  gaudit-app.c
  gaudit-window.c
  gaudit-task.c
  gaudit-task-page.c
)
target_link_libraries(gaudit PRIVATE PkgConfig::ADWAITA gaudit_model gaudit_backend gaudit_probe gaudit_config)
install(TARGETS gaudit RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
