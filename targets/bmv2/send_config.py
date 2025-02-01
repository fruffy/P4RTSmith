import sys
from p4runtime_lib import helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from google.protobuf import text_format
from p4.v1 import p4runtime_pb2

# Load the config file
config_file = sys.argv[1]
with open(config_file, "r") as f:
    config = f.read()

# Parse the config
write_request = p4runtime_pb2.WriteRequest()
text_format.Parse(config, write_request)

# Connect to BMv2
switch = helper.P4RuntimeSwitchConnection("localhost", 50051, device_id=0)

# Send the config
switch.WriteRequest(write_request)

# Clean up
ShutdownAllSwitchConnections()