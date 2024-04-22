#include <uapi/linux/ptrace.h> // Include the header for user-space access to kernel tracepoints

// Define a BPF map of type hash to keep track of counts. The map uses process IDs (u32) as keys and the count (u64) as values.
BPF_HASH(counts, u32, u64);

// This function is the eBPF program that counts the number of execve system calls made by each process.
int count_execve_calls(struct pt_regs *ctx) {
    // Retrieve the current process ID by shifting the combined PID/TGID value right by 32 bits.
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 counter = 0, *val; // Initialize a counter and a pointer to hold the current count value from the map.

    // Look up the current count for this PID in the 'counts' map.
    val = counts.lookup(&pid);
    if (val) {
        // If an entry exists, retrieve the current count.
        counter = *val;
    }
    counter++; // Increment the count.

    // Update the 'counts' map with the new count for this PID.
    counts.update(&pid, &counter);

    return 0; // Return 0 to indicate the program executed successfully.
}
