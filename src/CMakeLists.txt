add_library(iota_cclient
	"network/http_linux.c"
	"network/http_buffer.c"
)

target_include_directories(iota_cclient PUBLIC 
	${PROJECT_SOURCE_DIR}/src 
	${IOTA_CLIENT_EXTERNAL_HEADERS}
)

add_dependencies(iota_cclient iota_common)

set(IOTA_CLIENT_EXT_LIBS 
  iota_common
)

target_link_libraries(iota_cclient PUBLIC ${IOTA_CLIENT_EXT_LIBS})

if(HAS_ASAN_ENABLED)
  target_link_libraries(iota_cclient PUBLIC asan)
endif()

# install
install(TARGETS iota_common DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/src/" DESTINATION "${CMAKE_INSTALL_PREFIX}/include" FILES_MATCHING PATTERN "*.h")