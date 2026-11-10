# SPDX-License-Identifier: GPL-3.0-only
# Paths and the app ID are substituted first, then translations are merged in.

# Desktop entry: absolute Exec path, so launching never depends on PATH.
configure_file(gaudit.desktop.in ${CMAKE_CURRENT_BINARY_DIR}/gaudit.desktop.in @ONLY)
gaudit_i18n_merge(desktop
  ${CMAKE_CURRENT_BINARY_DIR}/gaudit.desktop.in
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.desktop)

# polkit action for the helper.
configure_file(gaudit.policy.in ${CMAKE_CURRENT_BINARY_DIR}/gaudit.policy.in @ONLY)
gaudit_i18n_merge(xml
  ${CMAKE_CURRENT_BINARY_DIR}/gaudit.policy.in
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.policy)

# GSettings schema. Developer builds compile it into the build tree and read
# it from there (a compiled-in path, never GSETTINGS_SCHEMA_DIR).
find_program(GLIB_COMPILE_SCHEMAS glib-compile-schemas REQUIRED)
string(REPLACE "." "/" GAUDIT_SCHEMA_PATH "${GAUDIT_APP_ID}")
configure_file(gaudit.gschema.xml.in
  ${CMAKE_CURRENT_BINARY_DIR}/schemas/${GAUDIT_APP_ID}.gschema.xml @ONLY)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/schemas/gschemas.compiled
  COMMAND ${GLIB_COMPILE_SCHEMAS} --strict ${CMAKE_CURRENT_BINARY_DIR}/schemas
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/schemas/${GAUDIT_APP_ID}.gschema.xml
  COMMENT "Compiling GSettings schema"
  VERBATIM)

add_custom_target(data ALL DEPENDS
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.desktop
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.policy
  ${CMAKE_CURRENT_BINARY_DIR}/schemas/gschemas.compiled)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/schemas/${GAUDIT_APP_ID}.gschema.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/glib-2.0/schemas)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.policy
        DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions)
