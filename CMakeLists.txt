cmake_minimum_required(VERSION 2.8)

project(psvimgtools C)

find_package(zlib REQUIRED)
find_package(Threads REQUIRED)

include_directories(${zlib_INCLUDE_DIRS})

# TODO: better check
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(i386)|(x86)|(x86_64)|(X86)")
    if(LINUX OR WIN32)
        add_subdirectory(intel)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAS_AESNI")
        set(aesni_libs intel-aesni)
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99")

add_executable(psvimg-extract psvimg-extract.c restore.c aes256.c sha256.c utils.c)
add_executable(psvmd-decrypt psvmd-decrypt.c restore.c aes256.c sha256.c utils.c)
add_executable(psvimg-create psvimg-create.c backup.c aes256.c sha256.c utils.c)

target_link_libraries(psvimg-extract ${zlib_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${aesni_libs})
target_link_libraries(psvmd-decrypt ${zlib_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${aesni_libs})
target_link_libraries(psvimg-create ${zlib_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${aesni_libs})

install(TARGETS psvimg-extract DESTINATION bin)
install(TARGETS psvmd-decrypt DESTINATION bin)
install(TARGETS psvimg-create DESTINATION bin)
