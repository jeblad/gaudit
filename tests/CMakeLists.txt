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

add_executable(test_probe_io test_probe_io.c)
target_link_libraries(test_probe_io PRIVATE gaudit_probe)
add_test(NAME probe-io COMMAND test_probe_io)

add_executable(test_sandbox test_sandbox.c)
target_compile_definitions(test_sandbox PRIVATE _GNU_SOURCE)
target_link_libraries(test_sandbox PRIVATE gaudit_sandbox)
add_test(NAME sandbox COMMAND test_sandbox)

add_executable(test_nft test_nft.c)
target_compile_definitions(test_nft PRIVATE _GNU_SOURCE)
target_link_libraries(test_nft PRIVATE gaudit_sandbox)
add_test(NAME nft COMMAND test_nft)

add_executable(test_lease test_lease.c)
target_link_libraries(test_lease PRIVATE gaudit_sandbox)
add_test(NAME lease COMMAND test_lease)

add_executable(test_private_files test_private_files.c)
target_include_directories(test_private_files PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_private_files PRIVATE _GNU_SOURCE
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_private_files PRIVATE gaudit_backend)
add_test(NAME private-files COMMAND test_private_files)

add_executable(test_secret_scan test_secret_scan.c)
target_include_directories(test_secret_scan PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_secret_scan PRIVATE _GNU_SOURCE
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_secret_scan PRIVATE gaudit_backend)
add_test(NAME secret-scan COMMAND test_secret_scan)

add_executable(test_listening test_listening.c)
target_include_directories(test_listening PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_compile_definitions(test_listening PRIVATE _GNU_SOURCE
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_listening PRIVATE gaudit_backend)
add_test(NAME listening COMMAND test_listening)

add_test(NAME icons COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-icons.sh ${PROJECT_SOURCE_DIR})

find_program(DESKTOP_FILE_VALIDATE desktop-file-validate)
if(DESKTOP_FILE_VALIDATE)
  add_test(NAME desktop-file
           COMMAND ${DESKTOP_FILE_VALIDATE} ${PROJECT_BINARY_DIR}/data/${GAUDIT_APP_ID}.desktop)
endif()
