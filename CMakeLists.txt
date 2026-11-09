# SPDX-License-Identifier: GPL-3.0-only
cmake_minimum_required(VERSION 3.25)

# The version lives in VERSION, which commit-and-tag-version bumps on release.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" GAUDIT_VERSION LIMIT_COUNT 1)
project(gaudit VERSION ${GAUDIT_VERSION} LANGUAGES C CXX)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS VERSION)

include(GNUInstallDirs)
include(CheckPIESupported)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

check_pie_supported()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- Project settings -------------------------------------------------------

# Fixed project identity, deliberately not a cache variable (see AGENTS.md).
set(GAUDIT_APP_ID "io.github.jeblad.gaudit")
set(GAUDIT_APP_NAME "gAudit")
set(GAUDIT_DEVELOPER "John Erling Blad")
set(GAUDIT_WEBSITE "https://github.com/jeblad/gaudit")
# License: GPL-3.0-only
set(GETTEXT_PACKAGE ${PROJECT_NAME})

# Developer builds read runtime data (translations) from the build tree.
# Never enable this for packaging: there is deliberately no environment
# variable override for these paths in any build.
option(GAUDIT_DEVELOPER_BUILD "Use build-tree paths for runtime data" OFF)

set(GAUDIT_BUILD_LOCALEDIR ${PROJECT_BINARY_DIR}/locale)
if(GAUDIT_DEVELOPER_BUILD)
  set(GAUDIT_LOCALEDIR ${GAUDIT_BUILD_LOCALEDIR})
else()
  set(GAUDIT_LOCALEDIR ${CMAKE_INSTALL_FULL_LOCALEDIR})
endif()
set(GAUDIT_PKGLIBEXECDIR ${CMAKE_INSTALL_FULL_LIBEXECDIR}/gaudit)
set(GAUDIT_HELPER_PATH ${GAUDIT_PKGLIBEXECDIR}/gaudit-helper)
set(GAUDIT_GUI_PATH ${CMAKE_INSTALL_FULL_BINDIR}/gaudit)

# --- Hardening and warnings -------------------------------------------------

add_compile_options(
  -Wall -Wextra -Wformat=2 -Werror=format-security -Wshadow
  -fstack-protector-strong -fstack-clash-protection
  "$<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes;-Wmissing-prototypes>"
  "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>"
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  add_compile_options(-fcf-protection)
endif()
add_link_options(
  LINKER:-z,relro LINKER:-z,now LINKER:-z,noexecstack LINKER:--as-needed
)

# --- Common -----------------------------------------------------------------

find_package(PkgConfig REQUIRED)

configure_file(src/config.h.in ${PROJECT_BINARY_DIR}/config.h @ONLY)
add_library(gaudit_config INTERFACE)
target_include_directories(gaudit_config INTERFACE ${PROJECT_BINARY_DIR})

include(cmake/I18n.cmake)

add_subdirectory(src/model)
add_subdirectory(src/backend)
add_subdirectory(src/probe)
add_subdirectory(src/helper)
add_subdirectory(src/orchestrator)
add_subdirectory(src/engine)
add_subdirectory(src/gui)
add_subdirectory(data)
if(GAUDIT_DEVELOPER_BUILD)
  add_subdirectory(tools)
endif()

enable_testing()
add_subdirectory(tests)
