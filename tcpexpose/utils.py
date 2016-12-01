from collections import namedtuple
import ctypes as ct

TASK_COMM_LEN = 16      # linux/sched.h
Quartet = namedtuple("Quartet", ["src_ip", "dst_ip", "src_port", "dst_port"])


class BaseEvent(ct.Structure):
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


class Event(object):
    def __init__(self, data):
        event = ct.cast(data, ct.POINTER(BaseEvent)).contents
        q = Quartet(
            event.saddr,
            event.daddr,
            event.ports >> 32,
            event.ports & 0xffffffff,
        )
        self.quartet = q
        self.base_event = event
