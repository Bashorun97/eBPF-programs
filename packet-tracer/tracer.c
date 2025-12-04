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
        if (func[i] == '\0')
            break;
        data.function[i] = func[i];
    }
    data.function[i] = '\0';

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
