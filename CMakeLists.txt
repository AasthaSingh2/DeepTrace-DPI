cmake_minimum_required(VERSION 3.16)

project(DeepTraceDPI VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(deeptrace_core
    src/blocking_engine.cpp
    src/dns_parser.cpp
    src/flow_tracker.cpp
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
)

target_include_directories(deeptrace_core PUBLIC include)

add_executable(deeptrace_dpi
    src/main.cpp
)

target_link_libraries(deeptrace_dpi PRIVATE deeptrace_core)

if(MSVC)
    target_compile_options(deeptrace_core PRIVATE /W4 /permissive-)
    target_compile_options(deeptrace_dpi PRIVATE /W4 /permissive-)
else()
    target_compile_options(deeptrace_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(deeptrace_dpi PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()

add_executable(deeptrace_tests
    tests/test_main.cpp
)

target_link_libraries(deeptrace_tests PRIVATE deeptrace_core)

if(MSVC)
    target_compile_options(deeptrace_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(deeptrace_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME deeptrace_tests COMMAND $<TARGET_FILE:deeptrace_tests>)
