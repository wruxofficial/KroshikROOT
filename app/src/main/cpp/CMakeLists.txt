cmake_minimum_required(VERSION 3.10.2)
project("kroshik")

add_library(
        kroshik
        SHARED
        kroshik.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        kroshik
        ${log-lib}
)
