cmake_minimum_required(VERSION 2.8)

project(intel-aesni C)
enable_language(ASM_NASM)

# Test 32/64 bits 
if("${CMAKE_C_SIZEOF_DATA_PTR}" EQUAL "8") 
   set(sz "64")
else("${CMAKE_C_SIZEOF_DATA_PTR}" EQUAL "8") 
   set(sz "32")
endif("${CMAKE_C_SIZEOF_DATA_PTR}" EQUAL "8")

if(NOT LINUX AND NOT WIN32)
    error("Intel's library only works on Linux and Windows")
endif()

if(CMAKE_ASM_NASM_COMPILER_LOADED)
    set(ASM_SOURCES asm/x${sz}/do_rdtsc.asm asm/x${sz}/iaesx64.asm)
endif(CMAKE_ASM_NASM_COMPILER_LOADED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -iquote ${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(intel-aesni intel_aes.c ${ASM_SOURCES})

install(TARGETS intel-aesni DESTINATION lib)
