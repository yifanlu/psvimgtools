cmake_minimum_required(VERSION 2.8)

project(psvimgtools C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(zlib REQUIRED)
find_package(LibGcrypt)

include_directories(${zlib_INCLUDE_DIRS})
include_directories(${LIBGCRYPT_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
if(${LIBGCRYPT_FOUND})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_GCRYPT")
else(${LIBGCRYPT_FOUND})
  set(sw_crypto aes256.c sha256.c)
  message(WARNING "libgcrypt was not found. Using slow software crypto.")
endif(${LIBGCRYPT_FOUND})

add_executable(psvimg-extract psvimg-extract.c restore.c utils.c ${sw_crypto})
add_executable(psvmd-decrypt psvmd-decrypt.c restore.c utils.c ${sw_crypto})
add_executable(psvimg-create psvimg-create.c backup.c utils.c ${sw_crypto})

target_link_libraries(psvimg-extract ${zlib_LIBRARIES} ${LIBGCRYPT_LIBRARIES})
target_link_libraries(psvmd-decrypt ${zlib_LIBRARIES} ${LIBGCRYPT_LIBRARIES})
target_link_libraries(psvimg-create ${zlib_LIBRARIES} ${LIBGCRYPT_LIBRARIES})

install(TARGETS psvimg-extract DESTINATION bin)
install(TARGETS psvmd-decrypt DESTINATION bin)
install(TARGETS psvimg-create DESTINATION bin)

if(${LIBGCRYPT_FOUND})
  add_executable(psvimg-keyfind psvimg-keyfind.c utils.c)
  set_target_properties(psvimg-keyfind PROPERTIES COMPILE_FLAGS "-O3")
  target_link_libraries(psvimg-keyfind ${LIBGCRYPT_LIBRARIES})
  install(TARGETS psvimg-keyfind DESTINATION bin)
endif(${LIBGCRYPT_FOUND})
