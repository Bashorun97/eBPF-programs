#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Define a structure to send data to Python userspace
struct data_t {
    u32 pid;          // The PID of the process (if available/relevant context)
    u32 tgid;
    u64 ts;           // Timestamp
    int stack_id;     // ID to look up the actual stack trace
    char comm[16];    // Command name
};

// Create a map to store stack traces. 
// 1024 is the max depth/entries.
BPF_STACK_TRACE(stack_traces, 1024);

// Event buffer to push data to userspace
BPF_PERF_OUTPUT(events);

// Hook into tcp_v4_do_rcv. 
// This is called when IPv4 hands a packet to TCP for a specific socket.
int trace_ingress(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    
    // Read the local port from the socket structure
    // sk->sk_num is stored in Host Byte Order
    u16 lport = sk->sk_num;

    // FILTER_PORT will be replaced by Python code dynamically
    if (lport != FILTER_PORT) {
        return 0;
    }

    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    
    // Since we are in SoftIRQ context, this usually returns 0 or ksoftirqd
    // But we capture it anyway for completeness.
    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    data.tgid = id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Capture the Kernel Stack Trace (0 = Kernel Stack, 1 = User Stack)
    data.stack_id = stack_traces.get_stackid(ctx, 0);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}