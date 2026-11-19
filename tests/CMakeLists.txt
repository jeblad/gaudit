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

add_executable(test_secrets_io test_secrets_io.c)
target_link_libraries(test_secrets_io PRIVATE gaudit_probe)
add_test(NAME secrets-io COMMAND test_secrets_io)

# The plugin's collection, compiled in from the orchestrator's mode.
add_executable(test_secrets_collect test_secrets_collect.c
               ${PROJECT_SOURCE_DIR}/src/plugins/private-files/orchestrator/secrets.c)
target_compile_definitions(test_secrets_collect PRIVATE _GNU_SOURCE)
target_include_directories(test_secrets_collect PRIVATE
                           ${PROJECT_SOURCE_DIR}/src/plugins/private-files/orchestrator
                           ${PROJECT_SOURCE_DIR}/src/probe)
target_link_libraries(test_secrets_collect PRIVATE gaudit_probe)
add_test(NAME secrets-collect COMMAND test_secrets_collect)

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
target_include_directories(test_private_files PRIVATE ${PROJECT_SOURCE_DIR}/src/plugins/private-files/backend)
target_compile_definitions(test_private_files PRIVATE _GNU_SOURCE
  GAUDIT_TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp")
target_link_libraries(test_private_files PRIVATE gaudit_backend)
add_test(NAME private-files COMMAND test_private_files)

add_executable(test_secret_scan test_secret_scan.c)
target_include_directories(test_secret_scan PRIVATE ${PROJECT_SOURCE_DIR}/src/plugins/private-files/backend)
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

add_executable(test_capability test_capability.c)
target_link_libraries(test_capability PRIVATE gaudit_backend gaudit_config)
add_test(NAME capability COMMAND test_capability)

add_executable(test_integrity test_integrity.c)
target_compile_definitions(test_integrity PRIVATE _GNU_SOURCE)
target_link_libraries(test_integrity PRIVATE gaudit_sandbox)
add_test(NAME integrity COMMAND test_integrity)

# The rule engine, built against the test rules plus the plugins' real ones.
set(TEST_RULES ${CMAKE_CURRENT_BINARY_DIR}/rules)
foreach(rule loop alloc io eval bad)
  configure_file(data/rules/${rule}/report.scm ${TEST_RULES}/${rule}/report.scm COPYONLY)
endforeach()
configure_file(${PROJECT_SOURCE_DIR}/src/plugins/private-files/rules/report.scm
               ${TEST_RULES}/core.private-files/report.scm COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/src/plugins/updates/rules/report.scm
               ${TEST_RULES}/core.updates/report.scm COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/src/plugins/shared-folder/rules/report.scm
               ${TEST_RULES}/core.shared-folder/report.scm COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/src/plugins/cloud/rules/report.scm
               ${TEST_RULES}/core.cloud/report.scm COPYONLY)
add_executable(test-engine ${PROJECT_SOURCE_DIR}/src/engine/main.c ${PROJECT_SOURCE_DIR}/src/engine/confine.c)
target_compile_definitions(test-engine PRIVATE _GNU_SOURCE ENGINE_RULES_DIR="${TEST_RULES}")
target_link_libraries(test-engine PRIVATE PkgConfig::GUILE gaudit_sandbox gaudit_config)
add_test(NAME engine COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/test_engine.sh
         $<TARGET_FILE:test-engine> ${CMAKE_CURRENT_SOURCE_DIR}/data/engine)

# The GUI's strict reading of a plugin's report (the view itself is not
# under test; its icon helper is stubbed).
pkg_check_modules(TEST_ADW REQUIRED IMPORTED_TARGET libadwaita-1)
add_executable(test_report test_report.c ${PROJECT_SOURCE_DIR}/src/gui/gaudit-report.c)
target_include_directories(test_report PRIVATE ${PROJECT_SOURCE_DIR}/src/gui)
target_link_libraries(test_report PRIVATE PkgConfig::TEST_ADW gaudit_backend gaudit_model gaudit_config)
add_test(NAME report COMMAND test_report ${CMAKE_CURRENT_SOURCE_DIR}/data/engine)

# The Private Files fixes, compiled in from the orchestrator's mode.
add_executable(test_fix test_fix.c ${PROJECT_SOURCE_DIR}/src/plugins/private-files/orchestrator/fix.c)
target_compile_definitions(test_fix PRIVATE _GNU_SOURCE)
target_include_directories(test_fix PRIVATE ${PROJECT_SOURCE_DIR}/src/plugins/private-files/orchestrator)
add_test(NAME fix COMMAND test_fix)

# Writing configuration as root: gAudit's own files only.
add_executable(test_conf_write test_conf_write.c ${PROJECT_SOURCE_DIR}/src/backend/debian/apt-conf.c)
target_compile_definitions(test_conf_write PRIVATE _GNU_SOURCE)
target_include_directories(test_conf_write PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/debian
                           ${PROJECT_SOURCE_DIR}/src/backend/include)
target_link_libraries(test_conf_write PRIVATE gaudit_sandbox)
add_test(NAME conf-write COMMAND test_conf_write)

# The Updates collection: line format and facts from a made-up backend.
add_executable(test_updates test_updates.c ${PROJECT_SOURCE_DIR}/src/plugins/updates/orchestrator/updates.c
               ${PROJECT_SOURCE_DIR}/src/plugins/updates/common/vendor.c)
target_compile_definitions(test_updates PRIVATE _GNU_SOURCE)
target_include_directories(test_updates PRIVATE ${PROJECT_SOURCE_DIR}/src/plugins/updates/orchestrator
                                           ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(test_updates PRIVATE gaudit_probe)
add_test(NAME updates COMMAND test_updates)

# The apt operations: what a fix page shows is what the helper runs.
add_executable(test_apt_ops test_apt_ops.c)
target_compile_definitions(test_apt_ops PRIVATE _GNU_SOURCE
    SOURCES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/apt-sources/upgraded/sources.list.d")
target_link_libraries(test_apt_ops PRIVATE gaudit_sandbox)
add_test(NAME apt-ops COMMAND test_apt_ops)

# Known vendor packages, the helper's side: the signed list, gpgv's status,
# the arguments, SHA-1, the shipped key, refusals before any signature.
add_executable(test_vendor test_vendor.c)
target_compile_definitions(test_vendor PRIVATE _GNU_SOURCE KEYS_DIR="${GAUDIT_BUILD_VENDOR_KEYS_DIR}"
    SIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/vendor/zoom-7.2.5.6661-gpgbuilder.asc")
target_link_libraries(test_vendor PRIVATE gaudit_sandbox)
add_dependencies(test_vendor vendor-keys)
add_test(NAME vendor COMMAND test_vendor)

# The GUI's environment: unwanted variables out, started again without them.
add_executable(test_environ test_environ.c ${PROJECT_SOURCE_DIR}/src/gui/gaudit-environ.c)
target_include_directories(test_environ PRIVATE ${PROJECT_SOURCE_DIR}/src/gui)
add_test(NAME environ COMMAND test_environ)

# A build that is not a developer build refuses to read or run anything from
# the build tree: configuring one with its install prefix inside the build
# tree must fail.
add_test(NAME release-paths
  COMMAND ${CMAKE_COMMAND} -S ${PROJECT_SOURCE_DIR} -B ${CMAKE_CURRENT_BINARY_DIR}/release-paths
          -DGAUDIT_DEVELOPER_BUILD=OFF
          -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/release-paths/inst)
set_tests_properties(release-paths PROPERTIES
  PASS_REGULAR_EXPRESSION "GAUDIT_HELPER_PATH")

# The orchestrator's filter: network sockets only when asked for.
add_executable(test_sandbox_net test_sandbox_net.c)
target_link_libraries(test_sandbox_net PRIVATE gaudit_sandbox)
add_test(NAME sandbox-net COMMAND test_sandbox_net)

# The signed manifest: signatures, format, time and version, files.
add_executable(test_manifest test_manifest.c)
target_link_libraries(test_manifest PRIVATE gaudit_sandbox)
add_test(NAME manifest COMMAND test_manifest)

# gAudit checking itself: the manifest's files, and the processes that ask.
add_executable(test_selfcheck test_selfcheck.c)
target_link_libraries(test_selfcheck PRIVATE gaudit_sandbox gaudit_probe)
add_test(NAME selfcheck COMMAND test_selfcheck)

# The names of the public share folder, generated from xdg-user-dirs' history.
add_executable(test_xdg_names test_xdg_names.c ${PROJECT_SOURCE_DIR}/src/backend/xdg-public-names.c)
target_include_directories(test_xdg_names PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
add_test(NAME xdg-names COMMAND test_xdg_names)

# The public share folder and the folders with a name it could have had.
add_executable(test_public_share test_public_share.c ${PROJECT_SOURCE_DIR}/src/backend/public-share.c
               ${PROJECT_SOURCE_DIR}/src/backend/xdg-public-names.c)
target_include_directories(test_public_share PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
add_test(NAME public-share COMMAND test_public_share)

# Shared Folder: its line format, and its collection on a home of the test's own.
add_executable(test_shared_folder test_shared_folder.c
               ${PROJECT_SOURCE_DIR}/src/plugins/shared-folder/orchestrator/shared.c)
target_include_directories(test_shared_folder PRIVATE
                           ${PROJECT_SOURCE_DIR}/src/plugins/shared-folder/orchestrator
                           ${PROJECT_SOURCE_DIR}/src/plugins/shared-folder/common
                           ${PROJECT_SOURCE_DIR}/src/backend ${PROJECT_SOURCE_DIR}/src/probe
                           ${PROJECT_SOURCE_DIR}/src/plugins/private-files/backend)
target_link_libraries(test_shared_folder PRIVATE gaudit_probe gaudit_backend)
add_test(NAME shared-folder COMMAND test_shared_folder)

# Cloud folders: each client's files as documented, on a home of the test's own.
add_executable(test_cloud_folders test_cloud_folders.c ${PROJECT_SOURCE_DIR}/src/backend/cloud-folders.c)
target_include_directories(test_cloud_folders PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
add_test(NAME cloud-folders COMMAND test_cloud_folders)

# Cloud Services: its line format, and its collection on a home of the test's own.
add_executable(test_cloud test_cloud.c ${PROJECT_SOURCE_DIR}/src/plugins/cloud/orchestrator/cloud.c)
target_include_directories(test_cloud PRIVATE ${PROJECT_SOURCE_DIR}/src/plugins/cloud/orchestrator
                           ${PROJECT_SOURCE_DIR}/src/plugins/cloud/common
                           ${PROJECT_SOURCE_DIR}/src/backend ${PROJECT_SOURCE_DIR}/src/probe
                           ${PROJECT_SOURCE_DIR}/src/plugins/private-files/backend)
target_link_libraries(test_cloud PRIVATE gaudit_probe gaudit_backend)
target_compile_definitions(test_cloud PRIVATE
  CLOUD_RULE="${PROJECT_SOURCE_DIR}/src/plugins/cloud/rules/report.scm")
add_test(NAME cloud COMMAND test_cloud)
