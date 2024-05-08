cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(kTLS C)

#set include and lib path
include_directories(include)
link_directories(lib64)

#subdir
add_subdirectory(src)
add_subdirectory(test)
