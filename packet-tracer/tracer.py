#!/usr/bin/python3
from bcc import BPF
from ctypes import Structure, c_uint, c_ulonglong, c_int, c_char
import ctypes as ct
import signal
import sys


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    int stack_id;
    char comm[TASK_COMM_LEN];
    char function[32];
};

BPF_STACK_TRACE(stack_traces, 2048);
BPF_PERF_OUTPUT(events);

static __always_inline int trace_packet(struct pt_regs *ctx, const char *func) {
    struct data_t data = {};
    u64 id = bpf_get_current_pid_tgid();

    data.pid = id >> 32;
    data.ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // copy function name
    int i;
    #pragma unroll
    for (i = 0; i < 31; i++) {
        if (func[i] == '\\0')
            break;
        data.function[i] = func[i];
    }
    data.function[i] = '\\0';

    data.stack_id = stack_traces.get_stackid(ctx, 0);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    return trace_packet(ctx, "tcp_sendmsg");
}

int kprobe__ip_output(struct pt_regs *ctx) {
    return trace_packet(ctx, "ip_output");
}

int kprobe____dev_queue_xmit(struct pt_regs *ctx) {
    return trace_packet(ctx, "__dev_queue_xmit");
}
"""

# ---------------------------------------------------------------------
# SIGNAL HANDLING
# ---------------------------------------------------------------------
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


try:
    b = BPF(text=bpf_text)
except Exception as e:
    print("Error loading BPF: ", e)
    sys.exit(1)

print("Tracing packet egress path...")
print("Run 'curl google.com' in another terminal.")
print("Press Ctrl+C to stop.\n")


class Data(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ts", c_ulonglong),
        ("stack_id", c_int),
        ("comm", c_char * 16),
        ("function", c_char * 32),
    ]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    if event.comm.decode() != 'curl':
        return
    
    print("-" * 60)
    print(f"[{event.comm.decode()} | PID {event.pid}]  →  {event.function.decode()}")
    print("Kernel stack:")

    try:
        for i, addr in enumerate(b["stack_traces"].walk(event.stack_id)):
            print(f"    #{i:02d}: {b.ksym(addr)}")
    except Exception:
        print("    <stack unavailable>")

# attach perf buffer
b["events"].open_perf_buffer(print_event)


if __name__ == "__main__":
    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\nStopping...")
            break