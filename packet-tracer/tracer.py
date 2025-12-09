#!/usr/bin/python3
from bcc import BPF
from ctypes import Structure, c_uint, c_ulonglong, c_int, c_char
import ctypes as ct
import signal
import sys



# ---------------------------------------------------------------------
# SIGNAL HANDLING
# ---------------------------------------------------------------------
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


try:
    b = BPF(src_file="tracer.c")
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