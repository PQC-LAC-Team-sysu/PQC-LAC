cmake_minimum_required(VERSION 3.5)
project(PQC)

set(CMAKE_CXX_STANDARD 20)
# 收集 lib 里的所有源文件
file(GLOB_RECURSE LIB_SOURCES "lib/*.cpp" "lib/*.cc")

add_executable(PQC main.cpp ${LIB_SOURCES})