cmake_minimum_required(VERSION 3.20)
project(rdcli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# Dependencies: vcpkg on Windows, pkg-config on Unix.
# protobuf via pkg-config on Unix so Abseil link deps (CHECK/DCHECK in Debug
# builds) are pulled in.
if(WIN32)
  find_package(unofficial-sodium CONFIG REQUIRED)
  find_package(zstd CONFIG REQUIRED)
  find_package(protobuf CONFIG REQUIRED)
  set(SODIUM_TARGET unofficial-sodium::sodium)
  set(ZSTD_TARGET $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
  set(PROTOBUF_TARGET protobuf::libprotobuf)
  set(WINSOCK_LIB ws2_32 advapi32)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
  pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
  pkg_check_modules(PROTOBUF REQUIRED IMPORTED_TARGET protobuf)
  set(SODIUM_TARGET PkgConfig::SODIUM)
  set(ZSTD_TARGET PkgConfig::ZSTD)
  set(PROTOBUF_TARGET PkgConfig::PROTOBUF)
  set(WINSOCK_LIB "")
endif()

set(CMAKE_THREAD_PREFER_PTHREAD ON)

# Protobuf sources are generated at build time so they always match the
# installed libprotobuf (checked-in gencode is pinned to one exact version).
# vcpkg exports protobuf::protoc; elsewhere use the protoc on PATH, which must
# come from the same protobuf installation as the library.
if(TARGET protobuf::protoc)
  set(PROTOC_BIN $<TARGET_FILE:protobuf::protoc>)
else()
  find_program(PROTOC_BIN protoc REQUIRED)
endif()
set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen/proto)
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})
set(PROTO_FILES ${PROTO_SRC_DIR}/message.proto ${PROTO_SRC_DIR}/rendezvous.proto)
set(PROTO_GENERATED
  ${PROTO_GEN_DIR}/message.pb.cc ${PROTO_GEN_DIR}/message.pb.h
  ${PROTO_GEN_DIR}/rendezvous.pb.cc ${PROTO_GEN_DIR}/rendezvous.pb.h
)
add_custom_command(
  OUTPUT ${PROTO_GENERATED}
  COMMAND ${PROTOC_BIN} --cpp_out=${PROTO_GEN_DIR} -I ${PROTO_SRC_DIR} ${PROTO_FILES}
  DEPENDS ${PROTO_FILES}
  COMMENT "Generating protobuf C++ sources"
)

set(CORE_SOURCES
  src/core/codec.cpp
  src/core/crypt.cpp
  src/core/secure.cpp
  src/core/addr_mangle.cpp
  src/core/rendezvous.cpp
  src/core/nat.cpp
  src/core/conn.cpp
  src/core/tunnel.cpp
  src/core/file_transfer.cpp
  src/core/terminal.cpp
  src/core/devices.cpp
  src/config/config.cpp
  src/net/hostport.cpp
  ${PROTO_GEN_DIR}/message.pb.cc
  ${PROTO_GEN_DIR}/rendezvous.pb.cc
)

# Platform-specific translation units.
if(WIN32)
  list(APPEND CORE_SOURCES src/net/socket_win.cpp)
else()
  list(APPEND CORE_SOURCES src/net/socket_posix.cpp)
endif()

add_library(rdcli_core STATIC ${CORE_SOURCES})
target_include_directories(rdcli_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/gen
)
target_link_libraries(rdcli_core PUBLIC
  ${PROTOBUF_TARGET}
  ${SODIUM_TARGET}
  ${ZSTD_TARGET}
  CURL::libcurl
  Threads::Threads
  ${WINSOCK_LIB}
)
if(WIN32)
  target_compile_definitions(rdcli_core PUBLIC SODIUM_STATIC CURL_STATICLIB)
else()
  target_compile_definitions(rdcli_core PRIVATE SODIUM_STATIC=1)
endif()

add_executable(rdcli src/main.cpp)
target_link_libraries(rdcli PRIVATE rdcli_core)

enable_testing()
add_subdirectory(tests)
