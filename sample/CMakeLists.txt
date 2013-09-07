cmake_minimum_required(VERSION 2.6)

PROJECT(plumage)

message(${CMAKE_SYSTEM})
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    include_directories(/usr/include  /usr/local/include ../picojson)
    link_directories(/usr/lib /usr/local/lib)
    add_definitions(-DUNIX)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    include_directories(/opt/local/include /usr/include /usr/local/include ../picojson)
    link_directories(/opt/local/lib /usr/lib /usr/local/lib)
    add_definitions(-DMAC_OSX)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set(CMAKE_CXX_FLAGS "-g")

ADD_EXECUTABLE(webapi_sample sample.cpp)

set_target_properties(webapi_sample PROPERTIES COMPILE_FLAGS "-Wall -I ../include -std=c++11 -stdlib=libc++")

set_target_properties(webapi_sample PROPERTIES LINK_FLAGS "-L ../lib -lplumage -ldl -lc++ -lcurl -lplumage_webapi -lssl -lcrypto")

