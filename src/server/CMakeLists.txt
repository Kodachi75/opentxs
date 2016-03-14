# Copyright (c) Monetas AG, 2014

include_directories(SYSTEM
  ${ZEROMQ_INCLUDE_DIRS}
  ${CZMQ_INCLUDE_DIR}
)

set(cxx-sources
  ServerSettings.cpp
  ConfigLoader.cpp
  PayDividendVisitor.cpp
  ClientConnection.cpp
  MessageProcessor.cpp
  MainFile.cpp
  UserCommandProcessor.cpp
  Notary.cpp
  Transactor.cpp
  OTServer.cpp
)

file(GLOB cxx-headers "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/server/*.hpp")

set(MODULE_NAME opentxs-server)
if(WIN32)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/windll.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
    @ONLY
  )

  # we have an extra Windows-specific file to compile
  add_library(${MODULE_NAME}
    ${cxx-sources}
    ${cxx-headers}
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
  )
else()
  add_library(${MODULE_NAME}
    ${cxx-sources}
    ${cxx-headers}
  )
endif()

target_link_libraries(opentxs-server PUBLIC opentxs-ext opentxs-cash opentxs-core opentxs-storage PRIVATE czmq_local)

if(WIN32)
  target_link_libraries(opentxs-server PUBLIC irrxml)
endif()

add_library(opentxs-proto SHARED IMPORTED)
add_library(opentxs-verify SHARED IMPORTED)

set_property(TARGET opentxs-proto PROPERTY IMPORTED_LOCATION ${OPENTXS_PROTO})
set_property(TARGET opentxs-verify PROPERTY IMPORTED_LOCATION ${OPENTXS_VERIFY})

target_link_libraries(opentxs-server PRIVATE opentxs-proto)
target_link_libraries(opentxs-server PRIVATE opentxs-verify)

set_lib_property(opentxs-server)

if(WIN32)
  add_custom_command(TARGET opentxs-server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/opentxs-server.dll"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/opentxs-server.dll")

  add_custom_command(TARGET opentxs-server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/opentxs-server.pdb"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/opentxs-server.pdb")
endif()

if(NOT WIN32)
  include(GNUInstallDirs)
  install(TARGETS opentxs-server
          DESTINATION ${CMAKE_INSTALL_LIBDIR}
          EXPORT opentxsTargets
          COMPONENT main)
endif()
