add_executable(rdcli_tests
  test_main.cpp
)

target_link_libraries(rdcli_tests PRIVATE rdcli_core ${SODIUM_TARGET} ${ZSTD_TARGET})

add_test(NAME rdcli_tests COMMAND rdcli_tests)
