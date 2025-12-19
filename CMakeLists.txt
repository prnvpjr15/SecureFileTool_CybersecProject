cmake_minimum_required(VERSION 3.10)
project(SecureFileTool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})

find_library(CRYPTOPP_LIB NAMES cryptopp cryptopp-static)

if(NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ library not found! Please install it.")
endif()


add_executable(SecureFileTool WIN32 src/main.cpp)

target_link_libraries(SecureFileTool ${wxWidgets_LIBRARIES} ${CRYPTOPP_LIB})