cmake_minimum_required(VERSION 3.20)
project(FirewallKeeper VERSION 1.0 LANGUAGES CXX)

# C++17 / C++20 / C++23 均可；默认 C++20
set(FK_CXX_STANDARD 20 CACHE STRING "C++ standard (17, 20, or 23)")
set_property(CACHE FK_CXX_STANDARD PROPERTY STRINGS 17 20 23)
set(CMAKE_CXX_STANDARD ${FK_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 统一 Boost >= 1.83（Debian apt 为 1.83；macOS 可用 1.88+）
# 示例: cmake -B build -DBoost_ROOT=/opt/homebrew/Cellar/boost/1.88.0
set(FK_BOOST_MIN_VERSION "1.83.0" CACHE STRING "Minimum Boost version")
if(NOT Boost_ROOT)
  if(APPLE)
    file(GLOB _fk_boost88 "/opt/homebrew/Cellar/boost/1.88*")
    if(_fk_boost88)
      list(GET _fk_boost88 0 Boost_ROOT)
    elseif(EXISTS "/opt/homebrew/opt/boost@1.88")
      set(Boost_ROOT "/opt/homebrew/opt/boost@1.88")
    endif()
  endif()
endif()
if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

find_package(nlohmann_json 3.11.0 QUIET CONFIG)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(yaml-cpp 0.8 QUIET CONFIG)
if(NOT yaml-cpp_FOUND)
  FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(yaml-cpp)
endif()

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost ${FK_BOOST_MIN_VERSION} REQUIRED COMPONENTS program_options filesystem)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/CloudSDKs.cmake)

message(STATUS "FirewallKeeper: C++${FK_CXX_STANDARD}, Boost ${Boost_VERSION}")

file(GLOB_RECURSE FK_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(FILTER FK_SOURCES EXCLUDE REGEX ".*/tests/.*")
list(FILTER FK_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")
list(FILTER FK_SOURCES EXCLUDE REGEX ".*/(tencentapi|awsapi|volcapi|aliyunapi|hetznercloud|hetznerrobot|scalewayapi|netcupapi)/.*")
list(FILTER FK_SOURCES EXCLUDE REGEX ".*/sdk/.*")

add_library(firewallkeeper_lib STATIC ${FK_SOURCES})
target_include_directories(firewallkeeper_lib PUBLIC include)
target_link_libraries(firewallkeeper_lib PUBLIC
  nlohmann_json::nlohmann_json
  yaml-cpp
  CURL::libcurl
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  Boost::program_options
  Boost::filesystem
  ${FK_CLOUD_SDK_LIBS}
)

add_executable(FirewallKeeper src/main.cpp)
target_link_libraries(FirewallKeeper PRIVATE firewallkeeper_lib Boost::program_options)

enable_testing()
add_executable(fk_state_test tests/state_test.cpp)
add_executable(fk_config_test tests/config_test.cpp)
target_link_libraries(fk_state_test PRIVATE firewallkeeper_lib)
target_link_libraries(fk_config_test PRIVATE firewallkeeper_lib)
add_test(NAME state_test COMMAND fk_state_test)
add_test(NAME config_test COMMAND fk_config_test)
