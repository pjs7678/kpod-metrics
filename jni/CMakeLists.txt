cmake_minimum_required(VERSION 3.16)
project(kpod_bpf C)

find_package(JNI REQUIRED)
find_library(LIBBPF_LIB bpf REQUIRED)
find_path(LIBBPF_INCLUDE bpf/libbpf.h REQUIRED)

add_library(kpod_bpf SHARED bpf_bridge.c)

target_include_directories(kpod_bpf PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${LIBBPF_INCLUDE}
)

target_link_libraries(kpod_bpf PRIVATE
    ${LIBBPF_LIB}
    elf
    z
)

target_compile_options(kpod_bpf PRIVATE -Wall -Wextra -Werror)

install(TARGETS kpod_bpf LIBRARY DESTINATION lib)
