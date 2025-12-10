#!/usr/bin/python3
import time
import sys
from bcc import BPF

TARGET_PORT = 8000

print(f"Targeting Ingress traffic on Local Port: {TARGET_PORT}")

try:
    with open("ingress.c", "r") as f:
        bpf_text = f.read()
except FileNotFoundError:
    sys.exit(1)

bpf_text = bpf_text.replace("FILTER_PORT", str(TARGET_PORT))

try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile BPF: {e}")
    sys.exit(1)

# tcp_v4_do_rcv is the function where the kernel handles TCP processing for a known socket
b.attach_kprobe(event="tcp_v4_do_rcv", fn_name="trace_ingress")

print("Tracing... Hit Ctrl-C to end.")
print("=" * 70)


def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm_str = event.comm.decode('utf-8', 'ignore')
    print("-" * 60)
    print(f"[{comm_str} | PID {event.pid}/{event.tgid}]  →  INGRESS (Target Port {TARGET_PORT})")
    print("Kernel stack:")

    try:
        for i, addr in enumerate(b["stack_traces"].walk(event.stack_id)):
            sym = b.ksym(addr).decode('utf-8', 'ignore')
            print(f"    #{i:02d}: {sym}")
    except Exception:
        print("    <stack unavailable>")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping tracing.")
        exit()