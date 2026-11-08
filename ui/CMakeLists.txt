cmake_minimum_required(VERSION 3.24)
project(dasm-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Qt >= 6.8 (ADR 0005). Do not use APIs newer than 6.8.
find_package(Qt6 6.8 REQUIRED COMPONENTS Core Gui Widgets Test)

include(FetchContent)

# cxx-qt-cmake: keep the tag in sync with cxx-qt in the workspace Cargo.toml.
FetchContent_Declare(CxxQt
    GIT_REPOSITORY https://github.com/KDAB/cxx-qt-cmake.git
    GIT_TAG 0.10.0)
FetchContent_MakeAvailable(CxxQt)

# Qt Advanced Docking System: system package first, else a pinned tag.
find_package(qtadvanceddocking-qt6 CONFIG QUIET)
if(NOT qtadvanceddocking-qt6_FOUND)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC ON CACHE BOOL "" FORCE)
    FetchContent_Declare(ads
        GIT_REPOSITORY https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System.git
        GIT_TAG v5.1.1
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(ads)
endif()

cxx_qt_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../crates/dasm-qt/Cargo.toml
    CRATES dasm-qt
    QT_MODULES Qt::Core Qt::Gui)

# The package is called `dasm-qt` (hyphen) but cxx-qt-cmake derives names
# with an underscore: export under the real crate name so that cxx-qt-build
# places the generated headers in <build>/cxxqt/crates/dasm-qt/include.
corrosion_set_env_vars(dasm_qt "CXX_QT_EXPORT_CRATE_dasm-qt=1")

# Same naming mismatch for the static-initializer object: cxx-qt-cmake looks
# for crates/dasm_qt/initializers.o, cxx-qt-build writes crates/dasm-qt/.
add_custom_target(dasm_qt_initializers_alias
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/cxxqt/crates/dasm-qt/initializers.o
        ${CMAKE_BINARY_DIR}/cxxqt/crates/dasm_qt/initializers.o
    DEPENDS cargo-build_dasm_qt)

add_library(dasm-ui STATIC
    src/Commands.cpp
    src/ListingView.cpp
    src/ListPanel.cpp
    src/MainWindow.cpp
    src/Palette.cpp)
add_dependencies(dasm-ui cargo-build_dasm_qt dasm_qt_initializers_alias)
target_include_directories(dasm-ui PUBLIC src ${CMAKE_BINARY_DIR}/cxxqt/crates/dasm-qt/include)
target_link_libraries(dasm-ui PUBLIC dasm_qt Qt6::Widgets ads::qtadvanceddocking-qt6)

add_executable(dasm-gui main.cpp)
target_link_libraries(dasm-gui PRIVATE dasm-ui)

enable_testing()
add_executable(dasm-smoke tests/smoke.cpp)
target_link_libraries(dasm-smoke PRIVATE dasm-ui Qt6::Test)
add_test(NAME smoke COMMAND dasm-smoke ${CMAKE_BINARY_DIR}/dasm-gui-screenshot.png)

# QtTest suites, one executable each (run with QT_QPA_PLATFORM=offscreen).
set(DASM_TESTS models palette nav listing editing bridge)
foreach(t IN LISTS DASM_TESTS)
    add_executable(test-${t} tests/test_${t}.cpp)
    target_include_directories(test-${t} PRIVATE tests)
    target_link_libraries(test-${t} PRIVATE dasm-ui Qt6::Test)
    add_test(NAME ${t} COMMAND test-${t})
endforeach()
set_tests_properties(smoke ${DASM_TESTS} PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 120)
