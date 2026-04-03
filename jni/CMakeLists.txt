cmake_minimum_required(VERSION 3.16)
project(kpod_bpf C)

# Find JNI headers manually (headless JDK doesn't include AWT which FindJNI requires)
find_path(JNI_INCLUDE_DIR jni.h HINTS $ENV{JAVA_HOME}/include REQUIRED)
find_path(JNI_PLATFORM_INCLUDE jni_md.h HINTS $ENV{JAVA_HOME}/include/linux REQUIRED)
set(JNI_INCLUDE_DIRS ${JNI_INCLUDE_DIR} ${JNI_PLATFORM_INCLUDE})

find_path(LIBBPF_INCLUDE bpf/libbpf.h REQUIRED)

# Always use shared libbpf — Ubuntu 24.04 ships libbpf.a without -fPIC
# on both x86_64 and arm64, which can't link into a shared library.
# The runtime stage copies libbpf.so into /app/lib/.
find_library(LIBBPF_LIB bpf REQUIRED)

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
