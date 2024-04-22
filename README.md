# eBPF Example

This repository contains a simple eBPF example that tracks process creation via the `clone` system call.

## Work In Progress (WIP)

Currently, the process monitoring functionality is under development and not working as expected. The eBPF program designed to hook into the `execve` system call is facing compilation issues due to redefinition errors between BCC and libbpf helper functions. 

## Environment Variables

Before building your Docker container, make sure to set the following environment variables in your Dockerfile:

```
ENV OBSERVE_ENDPOINT="your_observe_endpoint_here"
ENV OBSERVE_BEARER_TOKEN="your_bearer_token_here"
```

## Building the Docker Container

To build the Docker container, run:

```bash
docker build -t ebpf-<simple || process>-example -f <DOCKERFILE_NAME> .
```

`<DOCKERFILE_NAME>` options: 

- `Dockerfile.simple`: The eBPF program defined in `simple_ebpf.c` is designed to track the number of times the `execve` system call is invoked by different processes. It utilizes a BPF hash map (`counts`) to store and update the count of `execve` calls per process ID. Each time an `execve` call is made, the eBPF program increments the count for the corresponding process ID in the map.

- `Dockerfile.process`: The eBPF program is designed to hook into the `execve` system call via a tracepoint, which allows it to capture detailed information about each invocation of this call. The program records the process ID (`pid`), parent process ID (`ppid`), user ID (`uid`), return value (`retval`), exit status (`is_exit`), and the command executed (`comm`). This data is stored in a structure defined in the included header file (`execsnoop.h`), and each event is pushed to a BPF map of type `PERF_EVENT_ARRAY` for efficient cross-kernel/user-space communication.


### Running the Example

To run the example, execute:

```bash
docker run --rm --privileged -it -v /sys/kernel/debug:/sys/kernel/debug:rw ebpf-simple-example
```

Note: The --privileged flag is necessary to allow the Docker container to access the host's kernel modules.