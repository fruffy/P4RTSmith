if(ENABLE_TESTING)
  # Include the test subdirectory.
  message("-- Adding RTSmith v1model test suite.")
  include(test/P4Tests.cmake)
endif()

find_program(RTSMITH_DRIVER p4rtsmith)
if (NOT RTSMITH_DRIVER)
    message(FATAL_ERROR "RtSmith tool not found! Please ensure it is in your PATH.")
endif()

# Find p4c (for JSON generation)
find_program(P4C_EXECUTABLE p4c)
if (NOT P4C_EXECUTABLE)
    message(FATAL_ERROR "p4c not found! Please ensure it is in your PATH.")
endif()

# Source files for the main P4RtSmith.
set(RTSMITH_SOURCES
    ${RTSMITH_SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/constants.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/program_info.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/target.cpp
    PARENT_SCOPE
)

set(RTSMITH_LIBS ${RTSMITH_LIBS} ${P4C_LIBRARIES} ${P4C_LIB_DEPS} ${CMAKE_THREAD_LIBS_INIT} PARENT_SCOPE)

set(CONFIG_DIR "${CMAKE_BINARY_DIR}/rtsmith/configs")
set(JSON_DIR "${CMAKE_BINARY_DIR}/rtsmith/jsons")

file(MAKE_DIRECTORY ${CONFIG_DIR})
file(MAKE_DIRECTORY ${JSON_DIR})

file(GLOB P4_PROGRAMS
  # "${P4C_SOURCE_DIR}/testdata/p4_16_samples/*.p4"
  # "${P4C_SOURCE_DIR}/testdata/p4_16_samples/dash/*.p4"
  # "${P4C_SOURCE_DIR}/testdata/p4_16_samples/fabric_*/fabric.p4"
  # "${P4C_SOURCE_DIR}/testdata/p4_16_samples/omec/*.p4"
  # "${P4C_SOURCE_DIR}/testdata/p4_16_samples/pins/*.p4"
  # "${flay_SOURCE_DIR}/targets/bmv2/test/programs/*.p4"
  "${P4C_SOURCE_DIR}/testdata/p4_16_samples/dash/dash-pipeline-pna-dpdk.p4"
)

set(ALL_DEPENDENCIES "")

foreach(P4_PROGRAM ${P4_PROGRAMS})
    get_filename_component(PROGRAM_NAME ${P4_PROGRAM} NAME_WE)

    # Generate random config
    set(CONFIG_FILE "${CONFIG_DIR}/${PROGRAM_NAME}_init_config.txtpb")
    if (NOT CONFIG_FILE IN_LIST ALL_DEPENDENCIES)
        add_custom_command(
            OUTPUT ${CONFIG_FILE}
            COMMAND ${RTSMITH_DRIVER} ${P4_PROGRAM} --target bmv2 --arch v1model --output-dir ${CONFIG_DIR} --config-name ${PROGRAM_NAME} --random-seed
            DEPENDS ${P4_PROGRAM}
            COMMENT "Generating random config for ${PROGRAM_NAME}"
        )
        list(APPEND ALL_DEPENDENCIES ${CONFIG_FILE})
    endif()

    # Compile P4 program
    set(JSON_FILE "${JSON_DIR}/${PROGRAM_NAME}.json")
    if (NOT JSON_FILE IN_LIST ALL_DEPENDENCIES)
        add_custom_command(
            OUTPUT ${JSON_FILE}
            COMMAND ${P4C_EXECUTABLE} --target bmv2 --arch v1model --output "${JSON_DIR}/${PROGRAM_NAME}.json" ${P4_PROGRAM}
            DEPENDS ${P4_PROGRAM}
            COMMENT "Compiling ${PROGRAM_NAME} to JSON"
        )
        list(APPEND ALL_DEPENDENCIES ${JSON_FILE})
    endif()
endforeach()

# Step 3: Run BMv2 with the config
add_custom_target(
    run_all
    COMMAND ${CMAKE_SOURCE_DIR}/run_bmv2.sh "${JSON_DIR}" "${CONFIG_DIR}"
    DEPENDS ${ALL_DEPENDENCIES}
    COMMENT "Running BMv2 for all programs"
)