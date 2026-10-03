cmake_minimum_required(VERSION 3.15)
project(hzprotect LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
  message(FATAL_ERROR "HZProtect is Windows-only")
endif()

# Header-only SDK.
add_library(hzprotect INTERFACE)
target_include_directories(hzprotect INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src/sdk)

# Tools.
add_executable(hzkeygen  src/tools/hzkeygen.cpp)
add_executable(hzblob    src/tools/hzblob.cpp)
add_executable(hzstamp   src/tools/hzstamp.cpp)
add_executable(hzlicense src/tools/hzlicense.cpp)
target_include_directories(hzblob    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(hzstamp   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(hzlicense PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(GEN ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN})

# Per-build keys: regenerated on every configure/build (always out of date).
add_custom_command(
  OUTPUT ${GEN}/hz_build_keys.h ${GEN}/hz_build_key.bin
  COMMAND hzkeygen ${GEN}/hz_build_keys.h ${GEN}/hz_build_key.bin
  DEPENDS hzkeygen
  COMMENT "hzkeygen: generating per-build key material")

# Encrypt the demo asset with the per-build key.
add_custom_command(
  OUTPUT ${GEN}/config_blob.h
  COMMAND hzblob ${CMAKE_CURRENT_SOURCE_DIR}/test/assets/config.json ${GEN}/config_blob.h config_blob ${GEN}/hz_build_key.bin
  DEPENDS hzblob ${GEN}/hz_build_key.bin ${CMAKE_CURRENT_SOURCE_DIR}/test/assets/config.json
  COMMENT "hzblob: encrypting config.json")

add_executable(hzdemo test/demo.cpp ${GEN}/hz_build_keys.h ${GEN}/config_blob.h)
target_include_directories(hzdemo PRIVATE ${GEN})
target_link_libraries(hzdemo PRIVATE hzprotect)

# Self-contained tests (no files/tools needed).
add_executable(hooktest test/hooktest.cpp)
add_executable(edtest   test/edtest.cpp)
add_executable(lickat   test/lickat.cpp)
target_link_libraries(hooktest PRIVATE hzprotect)
target_link_libraries(edtest   PRIVATE hzprotect)
target_link_libraries(lickat   PRIVATE hzprotect)

if(MSVC)
  foreach(t hzkeygen hzblob hzstamp hzlicense hzdemo hooktest edtest lickat)
    target_compile_options(${t} PRIVATE /W4 /permissive-)
  endforeach()
endif()

# Stamp the demo's .text digest right after it links.
add_custom_command(TARGET hzdemo POST_BUILD
  COMMAND hzstamp $<TARGET_FILE:hzdemo>
  COMMENT "hzstamp: baking .text digest into hzdemo")

enable_testing()
add_test(NAME demo_runs COMMAND hzdemo)
set_tests_properties(demo_runs PROPERTIES PASS_REGULAR_EXPRESSION "verify_stamp\\(\\) = OK")
add_test(NAME hook_detection COMMAND hooktest)
set_tests_properties(hook_detection PROPERTIES PASS_REGULAR_EXPRESSION "ALL PASS")
add_test(NAME ed25519_kat COMMAND edtest)
set_tests_properties(ed25519_kat PROPERTIES PASS_REGULAR_EXPRESSION "ALL PASS")
add_test(NAME license_checks COMMAND lickat)
set_tests_properties(license_checks PROPERTIES PASS_REGULAR_EXPRESSION "ALL PASS")
