import asyncio
import logging
from bpf_manager import BPFManager
from ipc_manager import IPCManager


def command_line_runner():
    logging.basicConfig(level=logging.INFO)
    # TODO: Parse comm filter
    loop = asyncio.get_event_loop()
    ipcman = IPCManager(loop)
    loop.create_task(ipcman.run())
    bpfman = BPFManager(loop, "/../bcc_source/tcpexpose.c", "curl", ipcman.mailbox)
    loop.create_task(bpfman.run())
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    command_line_runner()
