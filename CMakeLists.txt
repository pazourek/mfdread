cmake_minimum_required(VERSION 2.8)

project(mfdread)

set(SRC main.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

add_executable(mfdread ${SRC})
install(TARGETS mfdread DESTINATION bin)
