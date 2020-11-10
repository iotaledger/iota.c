add_library(iota_client STATIC)
# the required minimum C standard
set_target_properties(iota_client PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_client
  PRIVATE "network/http_buffer.c"
          "network/http_curl.c"
          "api/get_node_info.c"
          "api/json_utils.c"
          "api/response_error.c"
          "api/get_message_hash.c"
          "api/get_tips.c"
  PUBLIC "network/http_buffer.h"
         "network/http.h"
         "api/get_node_info.h"
         "api/json_utils.h"
         "api/response_error.h"
         "api/get_message_hash.h"
         "api/get_tips.h"
         "client_service.h")

target_include_directories(iota_client PUBLIC
  "${PROJECT_SOURCE_DIR}/src"
  "${CURL_INCLUDE_DIRS}"
  "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_client iota_core ext_cjson)

target_link_libraries(
  iota_client
  INTERFACE ${CURL_LIBRARIES} cjson
  PUBLIC iota_core)

if(HAS_ASAN_ENABLED)
  target_link_libraries(iota_client PRIVATE asan)
endif()

# install client lib and headers
install(TARGETS iota_client DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/client/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/client"
  FILES_MATCHING
  PATTERN "*.h")
