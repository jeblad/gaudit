# SPDX-License-Identifier: GPL-3.0-only
# Targeted, hand-written tests (no framework).

add_executable(test_model test_model.c)
target_link_libraries(test_model PRIVATE gaudit_model)
add_test(NAME model COMMAND test_model)

add_executable(test_probe test_probe.c)
target_link_libraries(test_probe PRIVATE gaudit_probe)
add_test(NAME probe COMMAND test_probe)

add_executable(test_apt_conf test_apt_conf.c)
target_include_directories(test_apt_conf PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/ubuntu)
target_compile_definitions(test_apt_conf PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_apt_conf PRIVATE gaudit_backend)
add_test(NAME apt-conf COMMAND test_apt_conf)

add_executable(test_dpkg test_dpkg.c)
target_include_directories(test_dpkg PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/ubuntu)
target_compile_definitions(test_dpkg PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_dpkg PRIVATE gaudit_backend)
add_test(NAME dpkg COMMAND test_dpkg)

find_program(DESKTOP_FILE_VALIDATE desktop-file-validate)
if(DESKTOP_FILE_VALIDATE)
  add_test(NAME desktop-file
           COMMAND ${DESKTOP_FILE_VALIDATE} ${PROJECT_BINARY_DIR}/data/${GAUDIT_APP_ID}.desktop)
endif()
