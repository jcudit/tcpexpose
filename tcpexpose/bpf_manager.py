import os
import sys
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct

TASK_COMM_LEN = 16      # linux/sched.h


class BPFManager(object):
    def __init__(self, loop, bcc_file, comm_filter):
        '''
        Initialize BPF Manager with location of BCC compilation source file and
        process name filter
        '''
        self.running = False
        self.loop = loop
        self.bcc_file = bcc_file
        self.bpf = self._init_bpf()

    def _render_source(self):
        '''
        Read the <filename>.c source file for BCC compilation
        '''
        root = os.path.dirname(os.path.realpath(sys.argv[0]))
        with open(root + self.bcc_file, 'r') as sourcefile:
            return sourcefile.read()

    def _init_bpf(self):
        '''
        Initialize BPF functionality by defining trace points and functions
        '''
        bpf_text = self._render_source()
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")
        b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
        b.attach_kprobe(
            event="tcp_rcv_established",
            fn_name="trace_tcp_rcv_established"
        )
        b["events"].open_perf_buffer(_print_event)
        return b

    async def run(self):
        if not self.running:
            print("%-6s %-12s %-2s %-16s %-16s %-5s %s" % ("PID", "COMM", "IP", "SADDR",
                "DADDR", "DPORT", "LAT(ms)"))
            self.running = True
        while True:
            await self.loop.run_in_executor(None, self.bpf.kprobe_poll)

def _print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f" % (event.pid, event.task,
        event.ip, inet_ntop(AF_INET6, event.saddr),
        inet_ntop(AF_INET6, event.daddr), event.ports & 0xffffffff,
        float(event.delta_us) / 1000))
    # print('{0} {1} {2} {3} {4} {5}'.format(event.rx_b / 1024, event.tx_b / 1024, event.segs_out, event.segs_in, event.rcv_tstamp, event.lsndtime))
    # print('{0} {1} {2} {3} {4}'.format(event.snd_wl1, event.snd_wnd, event.max_window, event.mss_cache, event.window_clamp))
    # print('{0} {1} {2} {3} {4}'.format(event.rcv_ssthresh, event.packets_out, event.retrans_out, event.max_packets_out, event.max_packets_seq))
    # print('{0} {1} {2}'.format(event.srtt_us, event.mdev_us, event.mdev_max_us))

class Event(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong * 2),
        ("daddr", ct.c_ulonglong * 2),
        ("ip", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        # Throughput
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("segs_out", ct.c_ulonglong),
        ("segs_in", ct.c_ulonglong),
        ("rcv_tstamp", ct.c_ulonglong),
        ("lsndtime", ct.c_ulonglong),
        # Windowing
        ("snd_wl1", ct.c_ulonglong),
        ("snd_wnd", ct.c_ulonglong),
        ("max_window", ct.c_ulonglong),
        ("mss_cache", ct.c_ulonglong),
        ("window_clamp", ct.c_ulonglong),
        ("rcv_ssthresh", ct.c_ulonglong),
        ("packets_out", ct.c_ulonglong),
        ("retrans_out", ct.c_ulonglong),
        ("max_packets_out", ct.c_ulonglong),
        ("max_packets_seq", ct.c_ulonglong),
        # RTT
        ("srtt_us", ct.c_ulonglong),
        ("mdev_us", ct.c_ulonglong),
        ("mdev_max_us", ct.c_ulonglong),
        # Congestion
    ]
