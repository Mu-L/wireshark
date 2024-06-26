# This code was copied from https://gitlab.kitware.com/cmake/cmake/raw/master/Modules/FindLibXml2.cmake
# and modified to support Wireshark Windows 3rd party packages

# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindLibXml2
-----------

Find the XML processing library (libxml2).

IMPORTED Targets
^^^^^^^^^^^^^^^^

This module defines :prop_tgt:`IMPORTED` target ``LibXml2::LibXml2``, if
libxml2 has been found.

Result variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``LIBXML2_FOUND``
  true if libxml2 headers and libraries were found
``LIBXML2_INCLUDE_DIR``
  the directory containing LibXml2 headers
``LIBXML2_INCLUDE_DIRS``
  list of the include directories needed to use LibXml2
``LIBXML2_LIBRARIES``
  LibXml2 libraries to be linked
``LIBXML2_DEFINITIONS``
  the compiler switches required for using LibXml2
``LIBXML2_XMLLINT_EXECUTABLE``
  path to the XML checking tool xmllint coming with LibXml2
``LIBXML2_VERSION_STRING``
  the version of LibXml2 found (since CMake 2.8.8)

Cache variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``LIBXML2_INCLUDE_DIR``
  the directory containing LibXml2 headers
``LIBXML2_LIBRARY``
  path to the LibXml2 library
#]=======================================================================]

include(FindWSWinLibs)
FindWSWinLibs("vcpkg-export-.*" LIBXML2_HINTS)

if (NOT USE_REPOSITORY) # else we'll find Strawberry Perl's pkgconfig
    # use pkg-config to get the directories and then use these values
    # in the find_path() and find_library() calls
    find_package(PkgConfig QUIET)
    PKG_CHECK_MODULES(PC_LIBXML QUIET libxml-2.0)
    set(LIBXML2_DEFINITIONS ${PC_LIBXML_CFLAGS_OTHER})
endif()

find_path(LIBXML2_INCLUDE_DIR NAMES libxml/xpath.h
   HINTS
   ${PC_LIBXML_INCLUDEDIR}
   ${PC_LIBXML_INCLUDE_DIRS}
   ${LIBXML2_HINTS}/include
   PATH_SUFFIXES libxml2
   )

find_path(ICONV_INCLUDE_DIR  NAMES iconv.h
   HINTS
   ${LIBXML2_HINTS}/include
   )

# CMake 3.9 and below used 'LIBXML2_LIBRARIES' as the name of
# the cache entry storing the find_library result.  Use the
# value if it was set by the project or user.
if(DEFINED LIBXML2_LIBRARIES AND NOT DEFINED LIBXML2_LIBRARY)
  set(LIBXML2_LIBRARY ${LIBXML2_LIBRARIES})
endif()

find_library(LIBXML2_LIBRARY NAMES xml2 libxml2 libxml2-2
   HINTS
   ${PC_LIBXML_LIBDIR}
   ${PC_LIBXML_LIBRARY_DIRS}
   ${LIBXML2_HINTS}/lib
   )

find_program(LIBXML2_XMLLINT_EXECUTABLE xmllint
   HINTS
   ${LIBXML2_HINTS}/bin
   )
# for backwards compat. with KDE 4.0.x:
set(XMLLINT_EXECUTABLE "${LIBXML2_XMLLINT_EXECUTABLE}")

if(PC_LIBXML_VERSION)
    set(LIBXML2_VERSION_STRING ${PC_LIBXML_VERSION})
elseif(LIBXML2_INCLUDE_DIR AND EXISTS "${LIBXML2_INCLUDE_DIR}/libxml/xmlversion.h")
    file(STRINGS "${LIBXML2_INCLUDE_DIR}/libxml/xmlversion.h" libxml2_version_str
         REGEX "^#define[\t ]+LIBXML_DOTTED_VERSION[\t ]+\".*\"")

    string(REGEX REPLACE "^#define[\t ]+LIBXML_DOTTED_VERSION[\t ]+\"([^\"]*)\".*" "\\1"
           LIBXML2_VERSION_STRING "${libxml2_version_str}")
    unset(libxml2_version_str)
endif()

set(LIBXML2_INCLUDE_DIRS ${LIBXML2_INCLUDE_DIR} ${PC_LIBXML_INCLUDE_DIRS} ${ICONV_INCLUDE_DIR})
set(LIBXML2_LIBRARIES ${LIBXML2_LIBRARY})

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibXml2
                                  REQUIRED_VARS LIBXML2_LIBRARY LIBXML2_INCLUDE_DIR
                                  VERSION_VAR LIBXML2_VERSION_STRING)

mark_as_advanced(LIBXML2_INCLUDE_DIR LIBXML2_LIBRARY LIBXML2_XMLLINT_EXECUTABLE)

if(LibXml2_FOUND)
    # Include transitive dependencies for static linking.
    if(UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a")
        list(APPEND LIBXML2_LIBRARIES ${PC_LIBXML_LIBRARIES})
    endif()

    if (NOT TARGET LibXml2::LibXml2)
        add_library(LibXml2::LibXml2 UNKNOWN IMPORTED)
        set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${LIBXML2_INCLUDE_DIRS}")
        set_property(TARGET LibXml2::LibXml2 APPEND PROPERTY IMPORTED_LOCATION "${LIBXML2_LIBRARY}")
    endif()
endif()

AddWSWinDLLS(LibXml2 LIBXML2_HINTS "libxml2*" "liblzma*")
