cmake_minimum_required(VERSION 3.18)

set(TARGET mod_pak_reloader)
project(${TARGET})

set(${TARGET}_Sources
        "${CMAKE_CURRENT_SOURCE_DIR}/src/dllmain.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/PakReloader.cpp"

        # imgui
        "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependencies/imgui/imgui.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependencies/imgui/imgui_draw.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependencies/imgui/imgui_tables.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependencies/imgui/imgui_widgets.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../Dependencies/imgui/misc/cpp/imgui_stdlib.cpp"
        )

add_library(${TARGET} SHARED ${${TARGET}_Sources})
target_include_directories(${TARGET} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${TARGET} PRIVATE ue4ss)
