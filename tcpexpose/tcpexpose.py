import asyncio
from bpf_manager import BPFManager


def command_line_runner():
    # TODO: Parse comm filter
    # TODO: Register IPC Manager
    loop = asyncio.get_event_loop()
    bpfman = BPFManager(loop, "/../bcc_source/tcpexpose.c", "curl")
    try:
        loop.run_until_complete(bpfman.run())
    finally:
        loop.close()

if __name__ == '__main__':
    command_line_runner()
