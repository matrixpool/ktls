cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(kTLS C)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(KernelHeaders)

set(CMAKE_C_FLAGS "-O0 -g -ggdb")
set(CPU "x86_64")

#set include and lib path
include_directories(include)
link_directories(lib64)

#subdir
add_subdirectory(src)
# add_subdirectory(modules)
add_subdirectory(test)
