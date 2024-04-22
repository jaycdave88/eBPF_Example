#!/usr/bin/env python3
import time
import os
import requests  # Import the requests library to make HTTP requests
from bcc import BPF  # Import the BPF module from the bcc library

# Load the eBPF program from a file
bpf_text = open('./ebpf_programs/simple_ebpf.c').read()
# Create a BPF instance with the eBPF program text
b = BPF(text=bpf_text)

# Attach the eBPF program to the execve system call. This will make the eBPF program run every time the execve syscall is called.
# "__arm64_sys_execve" is the name of the execve syscall in ARM64 architecture.
b.attach_kprobe(event="__arm64_sys_execve", fn_name="count_execve_calls")

# Retrieve the 'counts' hash map defined in the eBPF program. This map is used to store the count of execve calls per process ID.
clone_counts = b.get_table("counts")

# Define a function to send the counts data to a remote server via HTTP POST request and print the counts every second.
def send_counts():
    data = []  # Initialize an empty list to store the data
    # Iterate over each item in the 'counts' map
    for k, v in clone_counts.items():
        # Append a dictionary with the process ID and its corresponding execve call count to the data list
        data.append({"PID": k.value, "Clone Calls": v.value})
    # Prepare the JSON payload to be sent
    json_data = {"data": data}
    # Make an HTTP POST request to the specified URL with the JSON data
    response = requests.post(
        {os.getenv('OBSERVE_ENDPOINT')},  # The URL to send the data to
        headers={
            "Authorization": f"Bearer {os.getenv('OBSERVE_BEARER_TOKEN')}",  # Authorization header with the API token
            "Content-type": "application/json"  # Content-Type header specifying the payload is JSON
        },
        json=json_data  # The JSON payload
    )
    # Print the HTTP response status code to indicate whether the data was successfully sent
    print(f"Data sent with response status: {response.status_code}")

# Main loop to continuously send the counts data every second
try:
    while True:
        send_counts()  # Call the send_counts function to send the data and print the counts
        clone_counts.clear()  # Clear the counts map to start counting afresh for the next second
        time.sleep(1)  # Wait for 1 second before repeating the loop
except KeyboardInterrupt:  # Handle the KeyboardInterrupt exception to gracefully exit the loop when the script is interrupted
    pass
