# Library scanner tests: tmp dirs and fixtures only, never /games.

# Real PE fixtures built by an LLVM toolchain when available (llvm-rc +
# clang + lld-link). Without it the tests fall back to synthetic PEs only.
find_program(LLVM_RC_EXECUTABLE NAMES llvm-rc)
find_program(LLD_LINK_EXECUTABLE NAMES lld-link)
find_program(CLANG_EXECUTABLE NAMES clang)
set(PE_FIXTURE_SRC ${PROJECT_SOURCE_DIR}/tests/fixtures/library/pe)
set(PE_FIXTURE_DIR ${CMAKE_CURRENT_BINARY_DIR}/pe-fixtures)
set(PE_FIXTURES_AVAILABLE OFF)
if(LLVM_RC_EXECUTABLE AND LLD_LINK_EXECUTABLE AND CLANG_EXECUTABLE)
    set(PE_FIXTURES_AVAILABLE ON)
    set(PE_OUTPUTS
        ${PE_FIXTURE_DIR}/FixtureQuest.exe
        ${PE_FIXTURE_DIR}/FixtureQuest32.exe
        ${PE_FIXTURE_DIR}/FixtureTool.dll
        ${PE_FIXTURE_DIR}/NoVersion.exe
        ${PE_FIXTURE_DIR}/MultiLang.exe)
    add_custom_command(
        OUTPUT ${PE_OUTPUTS}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PE_FIXTURE_DIR}
        COMMAND ${LLVM_RC_EXECUTABLE} /fo ${PE_FIXTURE_DIR}/quest.res ${PE_FIXTURE_SRC}/fixture_quest.rc
        COMMAND ${LLVM_RC_EXECUTABLE} /fo ${PE_FIXTURE_DIR}/multilang.res ${PE_FIXTURE_SRC}/fixture_multilang.rc
        COMMAND ${CLANG_EXECUTABLE} --target=x86_64-pc-windows-msvc -c ${PE_FIXTURE_SRC}/stub.c -o ${PE_FIXTURE_DIR}/stub64.obj
        COMMAND ${CLANG_EXECUTABLE} --target=i686-pc-windows-msvc -c ${PE_FIXTURE_SRC}/stub.c -o ${PE_FIXTURE_DIR}/stub32.obj
        COMMAND ${LLD_LINK_EXECUTABLE} /nologo /machine:x64 /entry:mainCRTStartup /subsystem:windows /nodefaultlib
                /out:${PE_FIXTURE_DIR}/FixtureQuest.exe ${PE_FIXTURE_DIR}/stub64.obj ${PE_FIXTURE_DIR}/quest.res
        COMMAND ${LLD_LINK_EXECUTABLE} /nologo /machine:x86 /entry:mainCRTStartup /subsystem:windows /nodefaultlib
                /safeseh:no /out:${PE_FIXTURE_DIR}/FixtureQuest32.exe ${PE_FIXTURE_DIR}/stub32.obj ${PE_FIXTURE_DIR}/quest.res
        COMMAND ${LLD_LINK_EXECUTABLE} /nologo /machine:x64 /dll /noentry /nodefaultlib
                /out:${PE_FIXTURE_DIR}/FixtureTool.dll ${PE_FIXTURE_DIR}/stub64.obj ${PE_FIXTURE_DIR}/quest.res
        COMMAND ${LLD_LINK_EXECUTABLE} /nologo /machine:x64 /entry:mainCRTStartup /subsystem:console /nodefaultlib
                /out:${PE_FIXTURE_DIR}/NoVersion.exe ${PE_FIXTURE_DIR}/stub64.obj
        COMMAND ${LLD_LINK_EXECUTABLE} /nologo /machine:x64 /entry:mainCRTStartup /subsystem:windows /nodefaultlib
                /out:${PE_FIXTURE_DIR}/MultiLang.exe ${PE_FIXTURE_DIR}/stub64.obj ${PE_FIXTURE_DIR}/multilang.res
        DEPENDS ${PE_FIXTURE_SRC}/stub.c ${PE_FIXTURE_SRC}/fixture_quest.rc ${PE_FIXTURE_SRC}/fixture_multilang.rc
        COMMENT "Building PE fixtures with llvm-rc/lld-link"
        VERBATIM)
    add_custom_target(library-pe-fixtures DEPENDS ${PE_OUTPUTS})
else()
    message(STATUS "Library tests: llvm-rc/clang/lld-link not found, toolchain PE fixtures skipped")
endif()

foreach(suite parsers io store service api)
    add_executable(tst_library_${suite} tst_library_${suite}.cpp test_support.hpp)
    target_link_libraries(tst_library_${suite} PRIVATE 360io-library-core)
    if(PE_FIXTURES_AVAILABLE)
        add_dependencies(tst_library_${suite} library-pe-fixtures)
        target_compile_definitions(tst_library_${suite} PRIVATE THREESIXTY_PE_FIXTURE_DIR="${PE_FIXTURE_DIR}")
    endif()
    if(THREESIXTY_LIBURING_FOUND)
        target_compile_definitions(tst_library_${suite} PRIVATE THREESIXTY_TEST_EXPECT_LIBURING)
    endif()
    add_test(NAME library.${suite} COMMAND tst_library_${suite})
    set_tests_properties(library.${suite} PROPERTIES
        TIMEOUT 240
        FAIL_REGULAR_EXPRESSION "CHECK failed|CHECK_EQ failed"
        ENVIRONMENT "QT_LOGGING_RULES=threesixty.library.info=false")
endforeach()

# CLI end-to-end over a fake tree; offline mode needs --policy any.
if(THREESIXTY_LIBRARY_ALLOW_ANY_FS)
    add_executable(tst_library_cli tst_library_cli.cpp test_support.hpp)
    target_link_libraries(tst_library_cli PRIVATE 360io-library-core)
    target_compile_definitions(tst_library_cli PRIVATE THREESIXTY_LIBRARY_CLI="$<TARGET_FILE:360io-library>")
    add_dependencies(tst_library_cli 360io-library)
    add_test(NAME library.cli COMMAND tst_library_cli)
    set_tests_properties(library.cli PROPERTIES
        TIMEOUT 240
        FAIL_REGULAR_EXPRESSION "CHECK failed|CHECK_EQ failed"
        ENVIRONMENT "QT_LOGGING_RULES=threesixty.library.info=false")
endif()
