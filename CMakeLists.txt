cmake_minimum_required(VERSION 2.8)

project(psvimgtools C)

find_package(zlib REQUIRED)
find_package(Threads REQUIRED)

include_directories(${zlib_INCLUDE_DIRS})

if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(PUBLIC psvimgtools "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(psvimgtools "${CMAKE_THREAD_LIBS_INIT}")
endif()

set(CMAKE_C_FLAGS "-g -std=gnu99")

add_executable(psvimg-extract extract.c aes256.c sha256.c utils.c)

# TODO: better check
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(i386)|(x86)|(x86_64)|(X86)")
    if(LINUX OR WIN32)
        add_subdirectory(intel)
        target_link_libraries(psvimg-extract intel-aesni)
        set(CMAKE_C_FLAGS "-DHAS_AESNI")
    endif()
endif()

install(TARGETS psvimg-extract DESTINATION bin)
