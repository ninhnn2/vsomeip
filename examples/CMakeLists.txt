# Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)
set(EXAMPLE_CONFIG_FILES
    "../config/vsomeip.json"
    "../config/vsomeip-local.json"
    "../config/vsomeip-tcp-client.json"
    "../config/vsomeip-tcp-service.json"
    "../config/vsomeip-udp-client.json"
    "../config/vsomeip-udp-service.json"
)

# Examples
add_executable(request-sample request-sample.cpp ${EXAMPLE_CONFIG_FILES})
target_link_libraries(request-sample ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY})

add_executable(response-sample response-sample.cpp ${EXAMPLE_CONFIG_FILES})
target_link_libraries(response-sample ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY})

add_executable(subscribe-sample subscribe-sample.cpp ${EXAMPLE_CONFIG_FILES})
target_link_libraries(subscribe-sample ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY})

add_executable(notify-sample notify-sample.cpp ${EXAMPLE_CONFIG_FILES})
target_link_libraries(notify-sample ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY})

# DTLS benchmark: echo/sink service plus a driver that reports latency, throughput
# and process CPU time for one payload size per run.
add_executable(dtls-bench-service dtls-bench-service.cpp)
target_link_libraries(dtls-bench-service ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

add_executable(dtls-bench-client dtls-bench-client.cpp)
target_link_libraries(dtls-bench-client ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${DL_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

add_dependencies(examples request-sample response-sample subscribe-sample notify-sample dtls-bench-service dtls-bench-client)

install (
    TARGETS request-sample response-sample subscribe-sample notify-sample dtls-bench-service dtls-bench-client
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT bin
)

###################################################################################################
