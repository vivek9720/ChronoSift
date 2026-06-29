cmake_minimum_required(VERSION 3.16)

project(ChronoSift
    VERSION 1.0.0
    DESCRIPTION "Offline log and event forensics toolkit"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Language standard and warning configuration.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

option(CHRONOSIFT_BUILD_TOOLS "Build the command-line tools" ON)
option(CHRONOSIFT_BUILD_TESTS "Build the deterministic test suite" ON)
option(CHRONOSIFT_BUILD_FUZZERS "Build fuzz harnesses with the local standalone driver" OFF)
option(CHRONOSIFT_SANITIZE "Enable address+undefined sanitizers" OFF)

if(CHRONOSIFT_SANITIZE AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Core library: every module compiled into one static archive.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE CHRONOSIFT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(chronosift STATIC ${CHRONOSIFT_SOURCES})
target_include_directories(chronosift PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

# ---------------------------------------------------------------------------
# Command-line tools: one executable per file in tools/.
# ---------------------------------------------------------------------------
if(CHRONOSIFT_BUILD_TOOLS)
    file(GLOB CHRONOSIFT_TOOLS CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/*.cpp")
    foreach(tool_src ${CHRONOSIFT_TOOLS})
        get_filename_component(tool_name "${tool_src}" NAME_WE)
        add_executable(${tool_name} "${tool_src}")
        target_include_directories(${tool_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
        target_link_libraries(${tool_name} PRIVATE chronosift)
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Tests: one executable per tests/<module>/*.cpp, registered with CTest.
# ---------------------------------------------------------------------------
if(CHRONOSIFT_BUILD_TESTS)
    enable_testing()
    file(GLOB_RECURSE CHRONOSIFT_TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
    foreach(test_src ${CHRONOSIFT_TEST_SOURCES})
        get_filename_component(test_name "${test_src}" NAME_WE)
        add_executable(${test_name} "${test_src}")
        target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
        target_link_libraries(${test_name} PRIVATE chronosift)
        # The suite asserts on results, so keep assert() live even in optimized
        # build types that would otherwise define NDEBUG.
        if(MSVC)
            target_compile_options(${test_name} PRIVATE /UNDEBUG)
        else()
            target_compile_options(${test_name} PRIVATE -UNDEBUG)
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Optional local fuzz harness build. The canonical fuzz build is
# .clusterfuzzlite/build.sh; this target lets developers smoke-test the
# harnesses with an ordinary compiler using the in-tree standalone driver.
# ---------------------------------------------------------------------------
if(CHRONOSIFT_BUILD_FUZZERS)
    file(GLOB CHRONOSIFT_FUZZERS CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/*_fuzzer.cc")
    foreach(fuzz_src ${CHRONOSIFT_FUZZERS})
        get_filename_component(fuzz_name "${fuzz_src}" NAME_WE)
        add_executable(${fuzz_name} "${fuzz_src}"
            "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/standalone_driver.cc")
        target_link_libraries(${fuzz_name} PRIVATE chronosift)
    endforeach()
endif()
