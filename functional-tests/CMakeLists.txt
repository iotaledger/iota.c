if(IOTA_WALLET_ENABLE)

  add_executable(functional-tests "functional_app.c")

  set_target_properties(functional-tests PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

  target_include_directories(functional-tests PRIVATE "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include"
                                                      "${CMAKE_INSTALL_PREFIX}/include/cjson")

  add_dependencies(functional-tests iota_wallet)
  target_link_libraries(functional-tests PRIVATE iota_wallet)
endif()
