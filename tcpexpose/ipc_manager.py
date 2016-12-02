from asyncio import Queue
from utils import Event


class IPCManager(object):

    def __init__(self, loop):
        self.traces = {}
        self.mailbox = Queue(maxsize=0, loop=loop)

    async def register(self, src_ip, dst_ip, src_port, dst_port):
        q = ('register', Quartet(src_ip, dst_ip, src_port, dst_port))
        await self.mailbox.put(q)

    async def unregister(self, src_ip, dst_ip, src_port, dst_port):
        q = ('unregister', Quartet(src_ip, dst_ip, src_port, dst_port))
        await self.mailbox.put(q)

    async def publish(self, event):
        q = ('publish', event)
        await self.mailbox.put(q)

    async def run(self):
        while True:
            (action, quartet) = await self.mailbox.get()
            if action == 'register':
                pass
                # print('received')
                # self.traces[q] = []
            elif action == 'unregister':
                del self.traces[q]
            elif action == 'publish':
                q = Queue(event.saddr)
                self.traces[q].append(event)
