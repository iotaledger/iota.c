add_library(iota_crypto STATIC)
# the required minimum C standard
set_target_properties(iota_crypto PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_crypto
  PRIVATE "iota_crypto.c"
  PUBLIC "iota_crypto.h")

target_include_directories(iota_crypto PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

add_dependencies(iota_crypto sodium)

target_link_libraries(iota_crypto INTERFACE sodium)

if(__JEMALLOC_INCLUDED)
  add_dependencies(iota_crypto jemalloc)
  target_link_libraries(iota_crypto PUBLIC jemalloc${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
  target_compile_definitions(iota_crypto PUBLIC USE_JEMALLOC)
  target_link_options(iota_crypto PUBLIC -Wl,--no-as-needed -ldl)
endif()

# install headers
install(TARGETS iota_crypto DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(FILES "${PROJECT_SOURCE_DIR}/src/crypto/iota_crypto.h" DESTINATION "${CMAKE_INSTALL_PREFIX}/include/crypto")
