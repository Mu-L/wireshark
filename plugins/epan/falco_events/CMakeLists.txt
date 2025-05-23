# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(falco-events 0 9 2 0)

set(DISSECTOR_SRC
	packet-falco-events.c
	sinsp-span.cpp
)

set(DISSECTOR_HEADERS
	sinsp-span.h
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_stratoshark_plugin_library(falco-events epan)

target_include_directories(falco-events SYSTEM PRIVATE
	${SINSP_INCLUDE_DIRS}
)

if(WIN32)
	# libsinsp/dumper.h includes libscap/scap_savefile_api.h, which includes
	# libscap/scap_zlib.h.
	target_include_directories(falco-events SYSTEM PRIVATE ${ZLIB_INCLUDE_DIR})
endif()

target_link_libraries(falco-events
	epan
	${SINSP_LINK_LIBRARIES}
)

install_plugin(falco-events epan)

CHECKAPI(
	NAME
	  falco-events
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
