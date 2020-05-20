#[[
Copyright (c) 2020 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

if(UNIX AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT CMAKE_BUILD_TYPE))
    include(CheckCCompilerFlag)
    set(CMAKE_REQUIRED_LIBRARIES "asan")
    if (CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
        check_c_compiler_flag("-fsanitize=address" HAS_ASAN)
        if(HAS_ASAN)
            add_compile_options("-fsanitize=address" "-fno-omit-frame-pointer")
            set(HAS_ASAN_ENABLED ON CACHE BOOL "Asan has enabled on target" FORCE)
        else()
            message(WARNING "ASan is not supported")
        endif()

    endif()
else()
    message(WARNING "ASan is not supported on Windows or Release build")
endif()
