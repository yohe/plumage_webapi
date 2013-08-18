cmake_minimum_required(VERSION 2.6)

PROJECT(plumage_webapi)

IF(UNIX)
    include_directories(/usr/include /usr/local/include ./picojson/)
    link_directories(/usr/lib /usr/local/lib)
ENDIF(UNIX)
IF(APPLE)
    include_directories(/opt/local/include /usr/include /usr/local/include ./picojson/)
    link_directories(/opt/local/lib /usr/lib /usr/local/lib)
ENDIF(APPLE)

add_library(plumage_webapi SHARED
    src/plumage_web_api.cpp
    )

add_library(plumage_webapi_st STATIC
    src/plumage_web_api.cpp
    )

make_directory(lib)

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set_target_properties(plumage_webapi plumage_webapi_st PROPERTIES COMPILE_FLAGS "-Wall -I ./include -std=c++11 -stdlib=libc++")
set_target_properties(plumage_webapi PROPERTIES LINK_FLAGS "-lplumage -lc++ -ldl -lcurl")
set_target_properties(plumage_webapi_st PROPERTIES LINK_FLAGS "-lplumage -lc++ -ldl -lcurl")
set_target_properties(plumage_webapi PROPERTIES LIBRARY_OUTPUT_DIRECTORY "lib/")
set_target_properties(plumage_webapi_st PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "lib/")

#ADD_EXECUTABLE(plumage_sample sample/sample.cpp)
#set_target_properties(plumage_sample PROPERTIES COMPILE_FLAGS "-Wall -I ./include -std=gnu++11 -stdlib=libc++")
#set_target_properties(plumage_sample PROPERTIES LINK_FLAGS "-lplumage -ldl -lc++ -lcurl -L lib/ -lplumage_webapi")
