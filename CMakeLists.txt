cmake_minimum_required(VERSION 3.13)
project(ZFSin)

include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)
option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)

add_subdirectory(ZFSin)
add_subdirectory(zfsinstaller)