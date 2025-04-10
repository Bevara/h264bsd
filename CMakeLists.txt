cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)

add_definitions(-fpic)

set(USE_DEBUG "-g")
set(USE_FLAGS "${USE_DEBUG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${USE_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${USE_FLAGS}")

#set(CMAKE_BUILD_TYPE Release)
#set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra")
#set(CMAKE_C_FLAGS "-O3 -Wall -Wextra")

SET(h264bsd_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/dec_h264bsd.c
   #${CMAKE_CURRENT_SOURCE_DIR}/reframe_nalu.c
     ${CMAKE_CURRENT_SOURCE_DIR}/av_parsers.c
     ${CMAKE_CURRENT_SOURCE_DIR}/bitstream.c
)

SET(h264bsd_INCLUDE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

SET(h264bsd_LIB
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/libh264bsd.a
)


SET(h264bsd_FLAGS

)

add_filter(h264bsd
        "${h264bsd_SRC}"
        "${h264bsd_LIB}"
        []
        ""
        "${h264bsd_INCLUDE}"
        ""
        "1")
