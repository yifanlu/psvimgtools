cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

set(SHORT_NAME dump_partials)
project(${SHORT_NAME})
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "Dump Partials")
set(VITA_TITLEID  "DUMP0900D")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

add_executable(${SHORT_NAME}
  main.c
  ../sha256.c
)

target_link_libraries(${SHORT_NAME}
  taihen_stub
  SceDisplay_stub
  SceCtrl_stub
  SceGxm_stub
  SceAppUtil_stub
  SceCommonDialog_stub
)

vita_create_self(${SHORT_NAME}.self ${SHORT_NAME} UNSAFE)

add_executable(kernel
  kernel.c
)

target_link_libraries(kernel
  SceCpuForDriver_stub
  SceSblAuthMgrForKernel_stub
  SceSysmemForDriver_stub
)

set_target_properties(kernel
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__VITA_KERNEL__"
)(${SHORT_NAME} kernel)

vita_create_self(kernel.skprx kernel
  UNSAFE
  CONFIG ${CMAKE_SOURCE_DIR}/kernel.yml
)

vita_create_vpk(${SHORT_NAME}.vpk ${VITA_TITLEID} ${SHORT_NAME}.self
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}
  FILE ${CMAKE_CURRENT_BINARY_DIR}/kernel.skprx kernel.skprx
)

add_dependencies(${SHORT_NAME}.vpk kernel.skprx)
