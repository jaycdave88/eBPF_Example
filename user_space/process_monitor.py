#!/usr/bin/env python3
import time
import os
import requests
from bcc import BPF, PerfType, PerfSWConfig

# Load the eBPF program from a file
bpf_text = open('./ebpf_programs/process_event.c').read()
# Create a BPF instance with the eBPF program text
b = BPF(text=bpf_text)

# Define the structure of the event data from the eBPF program
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_int),
        ("ppid", ct.c_int),
        ("uid", ct.c_int),
        ("retval", ct.c_int),
        ("is_exit", ct.c_bool),
        ("comm", ct.c_char * TASK_COMM_LEN)
    ]

# Create a perf event array to capture the events from the eBPF program
b["events"] = bpf.PerfEventArray()

# Define a callback function to process each event and send it to the endpoint
def send_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    json_data = {
        "data": {
            "PID": event.pid,
            "PPID": event.ppid,
            "UID": event.uid,
            "RetVal": event.retval,
            "IsExit": event.is_exit,
            "Comm": event.comm.decode('utf-8', 'replace')
        }
    }
    response = requests.post(
        {os.getenv('OBSERVE_ENDPOINT')},
        headers={
            "Authorization": f"Bearer {os.getenv('OBSERVE_BEARER_TOKEN')}",
            "Content-type": "application/json"
        },
        json=json_data
    )
    print(f"Data sent with response status: {response.status_code}")

# Attach the callback to the perf event array
b["events"].open_perf_buffer(send_event)

# Main loop to continuously read events and send them to the endpoint
print("Listening for events...")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
