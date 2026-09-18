cmake_minimum_required(VERSION 3.16)
project(YQC_LAC C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -mssse3 -maes -msse4.1")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mssse3 -maes -msse4.1")

# OpenSSL：优先使用本机 MSYS2 MINGW64 路径；如果不存在则交给 CMake 自动查找
if(EXISTS "C:/msys64/mingw64/lib/libcrypto.a")
    set(OPENSSL_ROOT_DIR       "C:/msys64/mingw64")
    set(OPENSSL_INCLUDE_DIR    "C:/msys64/mingw64/include")
    set(OPENSSL_CRYPTO_LIBRARY "C:/msys64/mingw64/lib/libcrypto.a")
    message(STATUS "YQC-LAC: using local MSYS2 OpenSSL at C:/msys64/mingw64")
else()
    message(STATUS "YQC-LAC: local MSYS2 OpenSSL not found, letting CMake find system OpenSSL")
endif()
find_package(OpenSSL REQUIRED)

# 所有目标共用的源文件
set(YQC_LAC_SOURCES
        main.cpp
        src/poly.cpp
        src/sample.cpp
        src/ecc.cpp
        src/pke.cpp
        src/kem.cpp
        src/kex.cpp
        src/ake.cpp
        src/random.cpp
        src/aes256ctr.c
        src/bch.c
)

# 四个安全级别，各自一个 target
foreach(LVL LIGHT 128 192 256)
    add_executable(YQC_LAC_${LVL} ${YQC_LAC_SOURCES})
    target_include_directories(YQC_LAC_${LVL} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(YQC_LAC_${LVL} PRIVATE OpenSSL::Crypto)
    if(LVL STREQUAL "LIGHT")
        target_compile_definitions(YQC_LAC_${LVL} PRIVATE LAC_LIGHT)
    else()
        target_compile_definitions(YQC_LAC_${LVL} PRIVATE LAC${LVL})
    endif()
endforeach()