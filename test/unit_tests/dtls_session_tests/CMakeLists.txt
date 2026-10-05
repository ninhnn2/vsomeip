# Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project("unit_tests_dtls_session_tests" LANGUAGES CXX)

add_executable(
    ${PROJECT_NAME}
    main.cpp
    test_dtls_session.cpp
)

# dtls_session.hpp lays out its members per backend: this test must see the
# same backend define as the library, or it reads the wrong object layout.
target_compile_definitions(${PROJECT_NAME} PRIVATE ${VSOMEIP_DTLS_DEFINITIONS}
    DTLS_TEST_PKI_SCRIPT="${PROJECT_SOURCE_DIR}/pki.sh")

target_link_libraries(
    ${PROJECT_NAME}
    gtest
    ${VSOMEIP_NAME}-test
    ${Boost_LIBRARIES}
    ${VSOMEIP_DTLS_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    vsomeip_utilities
)

add_dependencies(build_unit_tests ${PROJECT_NAME})

add_test(
    NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME}
)
