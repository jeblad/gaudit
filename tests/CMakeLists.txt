# SPDX-License-Identifier: GPL-3.0-only
# Targeted, hand-written tests (no framework).

add_executable(test_model test_model.c)
target_link_libraries(test_model PRIVATE gaudit_model)
add_test(NAME model COMMAND test_model)

add_executable(test_probe test_probe.c)
target_link_libraries(test_probe PRIVATE gaudit_probe)
add_test(NAME probe COMMAND test_probe)

add_executable(test_apt_conf test_apt_conf.c)
target_include_directories(test_apt_conf PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/debian)
target_compile_definitions(test_apt_conf PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_apt_conf PRIVATE gaudit_backend)
add_test(NAME apt-conf COMMAND test_apt_conf)

add_executable(test_dpkg test_dpkg.c)
target_include_directories(test_dpkg PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/debian)
target_compile_definitions(test_dpkg PRIVATE _GNU_SOURCE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data"
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_dpkg PRIVATE gaudit_backend PkgConfig::COMPRESSION)
add_test(NAME dpkg COMMAND test_dpkg)

add_executable(test_flatpak test_flatpak.c)
target_include_directories(test_flatpak PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_flatpak PRIVATE _GNU_SOURCE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_flatpak PRIVATE gaudit_backend)
add_test(NAME flatpak COMMAND test_flatpak)

add_executable(test_os_release test_os_release.c)
target_include_directories(test_os_release PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_os_release PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_os_release PRIVATE gaudit_backend)
add_test(NAME os-release COMMAND test_os_release)

add_executable(test_package_systems test_package_systems.c)
target_compile_definitions(test_package_systems PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_package_systems PRIVATE gaudit_backend)
add_test(NAME package-systems COMMAND test_package_systems)

add_executable(test_snap test_snap.c)
target_include_directories(test_snap PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_snap PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_snap PRIVATE gaudit_backend)
add_test(NAME snap COMMAND test_snap)

add_executable(test_fedora test_fedora.c)
target_include_directories(test_fedora PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/fedora)
target_compile_definitions(test_fedora PRIVATE _GNU_SOURCE
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_fedora PRIVATE gaudit_backend)
add_test(NAME fedora COMMAND test_fedora)

add_executable(test_dnf test_dnf.c)
target_include_directories(test_dnf PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/fedora)
target_compile_definitions(test_dnf PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_dnf PRIVATE gaudit_backend)
add_test(NAME dnf COMMAND test_dnf)

add_executable(test_apt_sources test_apt_sources.c)
target_include_directories(test_apt_sources PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/debian)
target_compile_definitions(test_apt_sources PRIVATE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(test_apt_sources PRIVATE gaudit_backend)
add_test(NAME apt-sources COMMAND test_apt_sources)

add_executable(test_pacman test_pacman.c)
target_include_directories(test_pacman PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/arch)
target_compile_definitions(test_pacman PRIVATE _GNU_SOURCE
  GAUDIT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data"
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_pacman PRIVATE gaudit_backend)
add_test(NAME pacman COMMAND test_pacman)

find_program(DESKTOP_FILE_VALIDATE desktop-file-validate)
if(DESKTOP_FILE_VALIDATE)
  add_test(NAME desktop-file
           COMMAND ${DESKTOP_FILE_VALIDATE} ${PROJECT_BINARY_DIR}/data/${GAUDIT_APP_ID}.desktop)
endif()
