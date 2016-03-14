# Copyright (c) Monetas AG, 2014

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PEDANTIC_CXX_FLAGS}")

set(dependency_include_dir
  ${CMAKE_CURRENT_SOURCE_DIR}/../deps/
)

include_directories(SYSTEM
  ${dependency_include_dir}
  ${dependency_include_dir}/ChaiScript/include
  ${dependency_include_dir}/lucre/include
  ${dependency_include_dir}/czmq/include
)

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_subdirectory(storage)
add_subdirectory(core)
add_subdirectory(cash)
add_subdirectory(ext)
add_subdirectory(network)
add_subdirectory(client)
add_subdirectory(server)

if (NOT ANDROID)
  add_subdirectory(opentxs)
  add_subdirectory(opentxs-script)
endif()
