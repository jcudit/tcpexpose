import os
import sys
import logging
import functools

from asyncio import QueueEmpty
from utils import Quartet, Event, BaseEvent
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct


class BPFManager(object):
    def __init__(self, loop, bcc_file, comm_filter, ipc_manager_mailbox):
        '''
        Initialize BPF Manager with location of BCC compilation source file and
        process name filter
        '''
        self.running = False
        self.loop = loop
        self.bcc_file = bcc_file
        self.ipc_manager_mailbox = ipc_manager_mailbox
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
        b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
        b.attach_kprobe(
            event="tcp_rcv_established",
            fn_name="trace_tcp_rcv_established"
        )
        b["events"].open_perf_buffer(
            functools.partial(_receive_event, self.ipc_manager_mailbox)
        )
        return b

    async def run(self):
        if not self.running:
            header = "%-6s %-12s %-2s %-16s %-16s %-5s %s" % \
                ("PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)")
            logging.info(header)
            self.running = True
        while True:
            await self.loop.run_in_executor(None, self.bpf.kprobe_poll)


def _receive_event(ipc_manager_mailbox, cpu, data, size):
    # ev = ct.cast(data, ct.POINTER(BaseEvent)).contents
    # line = "%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f" % \
    #     (ev.pid, ev.task, ev.event_type, inet_ntop(AF_INET6, ev.saddr),
    #     inet_ntop(AF_INET6, ev.daddr), ev.ports & 0xffffffff,
    #     float(ev.delta_us) / 1000)
    # logging.info(line)
    event = Event(data)
    if event.action is not None:
        try:
            ipc_manager_mailbox.put_nowait(event)
        except QueueEmpty:
            # TODO: Increment metric
            pass
