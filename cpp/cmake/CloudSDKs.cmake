# 官方云厂商 C++ SDK 集成
# 无官方 C++ SDK 的 provider（Hetzner / Scaleway / Netcup / Aliyun SWAS）仍使用 libcurl REST 实现
# 注：Aliyun Darabonba V2 SDK 的 FetchContent 依赖链与最新 tea-cpp 不兼容，暂保留 REST

set(FK_CLOUD_SDK_LIBS "")

# ---------- AWS Lightsail ----------
find_package(AWSSDK REQUIRED COMPONENTS lightsail)
list(APPEND FK_CLOUD_SDK_LIBS aws-cpp-sdk-lightsail aws-cpp-sdk-core)
add_compile_definitions(FK_HAS_AWS_SDK=1)

# ---------- 火山引擎 VPC ----------
include(FetchContent)
FetchContent_Declare(
  volcengine_cpp_sdk
  GIT_REPOSITORY https://github.com/volcengine/volcengine-cpp-sdk.git
  GIT_TAG master
  GIT_SHALLOW TRUE
)
set(BUILD_PRODUCT "vpc" CACHE STRING "" FORCE)
set(SKIP_CORE "" CACHE STRING "" FORCE)
FetchContent_MakeAvailable(volcengine_cpp_sdk)

set(_FK_VOLC_SRC "${volcengine_cpp_sdk_SOURCE_DIR}")
set(_FK_VOLC_CORE_INC "${_FK_VOLC_SRC}/volcengine-cpp-sdk-core/include/volcengine/core")
# Linux 区分大小写：VpcClient.h 引用 VolcengineMetaData.h，实际文件为 VolcengineMetadata.h
if(EXISTS "${_FK_VOLC_CORE_INC}/VolcengineMetadata.h")
  if(NOT EXISTS "${_FK_VOLC_CORE_INC}/VolcengineMetaData.h")
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E create_symlink
        VolcengineMetadata.h
        "${_FK_VOLC_CORE_INC}/VolcengineMetaData.h"
    )
  endif()
endif()
target_include_directories(volcengine-cpp-sdk-core PUBLIC
  "${_FK_VOLC_SRC}/volcengine-cpp-sdk-core/include"
)
if(TARGET volcengine-cpp-sdk-vpc)
  target_include_directories(volcengine-cpp-sdk-vpc PUBLIC
    "${_FK_VOLC_SRC}/volcengine-cpp-sdk-core/include"
    "${_FK_VOLC_SRC}/volcengine-cpp-sdk-vpc/include"
  )
  add_dependencies(volcengine-cpp-sdk-vpc volcengine-cpp-sdk-core)
endif()
# GCC 下 volcengine 头文件缺少 #include <memory>
foreach(_fk_volc_tgt IN ITEMS volcengine-cpp-sdk-core volcengine-cpp-sdk-vpc)
  if(TARGET ${_fk_volc_tgt})
    target_compile_options(${_fk_volc_tgt} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-include;memory>")
  endif()
endforeach()

list(APPEND FK_CLOUD_SDK_LIBS volcengine-cpp-sdk-core volcengine-cpp-sdk-vpc)
add_compile_definitions(FK_HAS_VOLCENGINE_SDK=1)

# ---------- 腾讯云 Lighthouse + VPC ----------
# volcengine 会 FORCE 写入 TARGET_OUTPUT_NAME_PREFIX，需先恢复腾讯云前缀
set(TARGET_OUTPUT_NAME_PREFIX "tencentcloud-sdk-cpp-" CACHE STRING "" FORCE)
FetchContent_Declare(
  tencentcloud_sdk_cpp
  GIT_REPOSITORY https://github.com/TencentCloud/tencentcloud-sdk-cpp.git
  GIT_TAG 3.0.822
  GIT_SHALLOW TRUE
)
set(BUILD_MODULES "lighthouse;vpc" CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_FUNCTION_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tencentcloud_sdk_cpp)

set(_FK_TENCENT_SRC "${tencentcloud_sdk_cpp_SOURCE_DIR}")
target_include_directories(core PUBLIC "${_FK_TENCENT_SRC}/core/include")
foreach(_fk_tc_mod IN ITEMS core lighthouse vpc)
  if(TARGET ${_fk_tc_mod})
    target_include_directories(${_fk_tc_mod} PUBLIC
      "${_FK_TENCENT_SRC}/core/include"
      "${_FK_TENCENT_SRC}/${_fk_tc_mod}/include"
    )
    if(NOT _fk_tc_mod STREQUAL "core")
      add_dependencies(${_fk_tc_mod} core)
    endif()
    # GCC 下 tencent core 头文件缺少 #include <cstdint>
    target_compile_options(${_fk_tc_mod} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-include;cstdint>")
  endif()
endforeach()

list(APPEND FK_CLOUD_SDK_LIBS core lighthouse vpc)
add_compile_definitions(FK_HAS_TENCENT_SDK=1)

message(STATUS "Cloud SDKs: AWS Lightsail, Volcengine VPC, Tencent Lighthouse/VPC; Aliyun SWAS via REST")
