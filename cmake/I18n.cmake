# SPDX-License-Identifier: GPL-3.0-only
# gettext-based i18n/l10n.
#
#   cmake --build --preset default --target pot        regenerate po/gaudit.pot
#   cmake --build --preset default --target update-po  regenerate .pot and merge into every .po
#
# .mo files are built into ${GAUDIT_BUILD_LOCALEDIR} as part of the normal build.

find_program(XGETTEXT_EXECUTABLE xgettext REQUIRED)
find_program(MSGFMT_EXECUTABLE msgfmt REQUIRED)
find_program(MSGMERGE_EXECUTABLE msgmerge REQUIRED)

set(GAUDIT_PO_DIR ${PROJECT_SOURCE_DIR}/po)
set(GAUDIT_POT ${GAUDIT_PO_DIR}/${GETTEXT_PACKAGE}.pot)

# One language code per line; '#' starts a comment line.
file(STRINGS ${GAUDIT_PO_DIR}/LINGUAS GAUDIT_LINGUAS REGEX "^[^#]")
list(TRANSFORM GAUDIT_LINGUAS STRIP)
list(FILTER GAUDIT_LINGUAS EXCLUDE REGEX "^$")

set(GAUDIT_PO_FILES)
foreach(lang IN LISTS GAUDIT_LINGUAS)
  list(APPEND GAUDIT_PO_FILES ${GAUDIT_PO_DIR}/${lang}.po)
endforeach()

# GETTEXTDATADIRS lets xgettext/msgfmt find our own ITS rules in po/its/
# (Ubuntu does not ship ITS rules for polkit policy files by default).
set(GAUDIT_GETTEXT_ENV ${CMAKE_COMMAND} -E env GETTEXTDATADIRS=${GAUDIT_PO_DIR})

add_custom_target(pot
  COMMAND ${GAUDIT_GETTEXT_ENV} ${XGETTEXT_EXECUTABLE}
          --from-code=UTF-8
          --add-comments=Translators
          --keyword=_ --keyword=N_ --keyword=C_:1c,2 --keyword=NC_:1c,2
          --package-name=${PROJECT_NAME}
          --package-version=${PROJECT_VERSION}
          --directory=${PROJECT_SOURCE_DIR}
          --files-from=${GAUDIT_PO_DIR}/POTFILES.in
          --output=${GAUDIT_POT}
  COMMENT "Extracting translatable strings to po/${GETTEXT_PACKAGE}.pot"
  VERBATIM)

set(_update_cmds)
foreach(po IN LISTS GAUDIT_PO_FILES)
  list(APPEND _update_cmds
       COMMAND ${MSGMERGE_EXECUTABLE} --quiet --update --backup=none ${po} ${GAUDIT_POT})
endforeach()
add_custom_target(update-po ${_update_cmds}
  COMMENT "Merging po/${GETTEXT_PACKAGE}.pot into translations"
  VERBATIM)
add_dependencies(update-po pot)

set(_mo_files)
foreach(lang IN LISTS GAUDIT_LINGUAS)
  set(_po ${GAUDIT_PO_DIR}/${lang}.po)
  set(_mo_dir ${GAUDIT_BUILD_LOCALEDIR}/${lang}/LC_MESSAGES)
  set(_mo ${_mo_dir}/${GETTEXT_PACKAGE}.mo)
  add_custom_command(OUTPUT ${_mo}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${_mo_dir}
    COMMAND ${MSGFMT_EXECUTABLE} --check --output-file=${_mo} ${_po}
    DEPENDS ${_po}
    COMMENT "Compiling translation ${lang}"
    VERBATIM)
  list(APPEND _mo_files ${_mo})
  install(FILES ${_mo} DESTINATION ${CMAKE_INSTALL_LOCALEDIR}/${lang}/LC_MESSAGES)
endforeach()
add_custom_target(translations ALL DEPENDS ${_mo_files})

# Merge translations into a data file template.
#   kind: "desktop" or "xml" (xml uses the ITS rules in po/its/)
function(gaudit_i18n_merge kind template output)
  add_custom_command(OUTPUT ${output}
    COMMAND ${GAUDIT_GETTEXT_ENV} ${MSGFMT_EXECUTABLE}
            --${kind} --template=${template} -d ${GAUDIT_PO_DIR} -o ${output}
    DEPENDS ${template} ${GAUDIT_PO_FILES} ${GAUDIT_PO_DIR}/LINGUAS
    VERBATIM)
endfunction()

# A plugin's own text domain: its report (rule files, Scheme: G_ and the
# plural pair N_) and its GUI code (C: P_). The plugin's po/ holds
# POTFILES.in (C files), RULES.in (rule files), LINGUAS and <lang>.po.
# Joins the pot/update-po targets, and builds its .mo files into the same
# locale directory, so the compiled-in path finds them.
function(gaudit_plugin_domain domain podir)
  set(_pot ${podir}/${domain}.pot)
  file(STRINGS ${podir}/LINGUAS _langs REGEX "^[^#]")
  list(TRANSFORM _langs STRIP)
  list(FILTER _langs EXCLUDE REGEX "^$")
  add_custom_target(pot-${domain}
    COMMAND ${XGETTEXT_EXECUTABLE} --from-code=UTF-8 --add-comments=Translators
            --language=C --keyword=P_ --package-name=${domain}
            --package-version=${PROJECT_VERSION} --directory=${PROJECT_SOURCE_DIR}
            --files-from=${podir}/POTFILES.in --output=${_pot}
    COMMAND ${XGETTEXT_EXECUTABLE} --from-code=UTF-8 --join-existing
            --language=Scheme --keyword=G_ --keyword=N_:1,2
            --directory=${PROJECT_SOURCE_DIR} --files-from=${podir}/RULES.in --output=${_pot}
    COMMENT "Extracting the strings of ${domain}"
    VERBATIM)
  add_dependencies(pot pot-${domain})
  set(_cmds)
  set(_mos)
  foreach(lang IN LISTS _langs)
    set(_po ${podir}/${lang}.po)
    list(APPEND _cmds COMMAND ${MSGMERGE_EXECUTABLE} --quiet --update --backup=none ${_po} ${_pot})
    set(_mo_dir ${GAUDIT_BUILD_LOCALEDIR}/${lang}/LC_MESSAGES)
    set(_mo ${_mo_dir}/${domain}.mo)
    add_custom_command(OUTPUT ${_mo}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${_mo_dir}
      COMMAND ${MSGFMT_EXECUTABLE} --check --output-file=${_mo} ${_po}
      DEPENDS ${_po}
      COMMENT "Compiling ${domain} translation ${lang}"
      VERBATIM)
    list(APPEND _mos ${_mo})
    install(FILES ${_mo} DESTINATION ${CMAKE_INSTALL_LOCALEDIR}/${lang}/LC_MESSAGES)
  endforeach()
  add_custom_target(update-po-${domain} ${_cmds} VERBATIM)
  add_dependencies(update-po-${domain} pot-${domain})
  add_dependencies(update-po update-po-${domain})
  add_custom_target(translations-${domain} ALL DEPENDS ${_mos})
endfunction()
