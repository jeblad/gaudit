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

add_custom_target(data ALL DEPENDS
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.desktop
  ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.policy)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${GAUDIT_APP_ID}.policy
        DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions)
