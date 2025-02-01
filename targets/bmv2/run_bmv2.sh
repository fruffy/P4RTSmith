#!/bin/bash

# Arguments
JSON_DIR=$1
CONFIG_DIR=$1

# Loop through all JSON files in the output directory
for JSON_FILE in ${JSON_DIR}/*.json; do
    # Get the program name (e.g., program1 from program1.json)
    PROGRAM_NAME=$(basename ${JSON_FILE} .json)

    # Start BMv2
    simple_switch -i 0@veth0 -i 1@veth1 ${JSON_FILE} &

    # Wait for BMv2 to start
    sleep 2

    # Send the config file to BMv2 using P4Runtime
    CONFIG_FILE="${CONFIG_DIR}/${PROGRAM_NAME}_init_config.txtpb"
    if [[ -f ${CONFIG_FILE} ]]; then
        python3 ${CMAKE_SOURCE_DIR}/send_config.py ${CONFIG_FILE}
    else
        echo "Config file not found: ${CONFIG_FILE}"
    fi
done