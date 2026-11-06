cmake_minimum_required(VERSION 3.21)
project(threesixtyio_public VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The public components currently require Linux")
endif()
include(CTest)
option(THREESIXTY_BUILD_LIBRARY "Build the library scanner and offline CLI" ON)
option(THREESIXTY_LIBRARY_ALLOW_ANY_FS "Allow synthetic test roots on any filesystem" OFF)
# The portable thread-pool backend avoids an optional dependency on liburing.
set(THREESIXTY_LIBURING_FOUND OFF)
if(THREESIXTY_BUILD_LIBRARY)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network)
    find_package(SQLite3 REQUIRED)
    qt_standard_project_setup(REQUIRES 6.4)
    add_library(360io-library-core STATIC
        src/daemon/library/acf_parser.cpp
        src/daemon/library/exe_rules.cpp
        src/daemon/library/inotify_watcher.cpp
        src/daemon/library/install_scanner.cpp
        src/daemon/library/io_engine.cpp
        src/daemon/library/library_api.cpp
        src/daemon/library/library_service.cpp
        src/daemon/library/library_store.cpp
        src/daemon/library/library_types.cpp
        src/daemon/library/pe_parser.cpp
        src/daemon/library/safe_fs.cpp
        src/daemon/library/sanitize.cpp)
    target_include_directories(360io-library-core PUBLIC src/daemon/library)
    target_link_libraries(360io-library-core PUBLIC Qt6::Core Qt6::Network SQLite::SQLite3)
    target_compile_options(360io-library-core PRIVATE -Wall -Wextra)
    add_executable(360io-library src/library_cli/main.cpp)
    target_link_libraries(360io-library PRIVATE 360io-library-core)
    if(THREESIXTY_LIBRARY_ALLOW_ANY_FS)
        target_compile_definitions(360io-library PRIVATE THREESIXTY_LIBRARY_ALLOW_ANY_FS)
    endif()
    if(BUILD_TESTING)
        add_subdirectory(tests/library)
    endif()
    install(TARGETS 360io-library RUNTIME DESTINATION bin)
endif()
add_library(360io-recovery-core STATIC src/recovery/recovery_detect.cpp)
target_include_directories(360io-recovery-core PUBLIC src/recovery)
add_executable(360io-recovery-detect src/recovery/main.cpp)
target_link_libraries(360io-recovery-detect PRIVATE 360io-recovery-core)
install(TARGETS 360io-recovery-detect RUNTIME DESTINATION bin)
if(BUILD_TESTING)
    add_executable(tst_recovery_detect tests/recovery/tst_recovery_detect.cpp)
    target_link_libraries(tst_recovery_detect PRIVATE 360io-recovery-core)
    add_test(NAME recovery.unit COMMAND tst_recovery_detect)
    set_tests_properties(recovery.unit PROPERTIES TIMEOUT 60)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    add_test(NAME shield.unit COMMAND ${Python3_EXECUTABLE} -B -m unittest discover -s tests -t tests
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tools/shield)
    set_tests_properties(shield.unit PROPERTIES TIMEOUT 120 ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
