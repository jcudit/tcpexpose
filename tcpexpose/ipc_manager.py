from asyncio import Queue
from utils import Event


class IPCManager(object):

    def __init__(self, loop):
        self.traces = {}
        self.mailbox = Queue(maxsize=0, loop=loop)

    # async def register(self, src_ip, dst_ip, src_port, dst_port):
    #     q = ('register', Quartet(src_ip, dst_ip, src_port, dst_port))
    #     await self.mailbox.put(q)
    #
    # async def unregister(self, src_ip, dst_ip, src_port, dst_port):
    #     q = ('unregister', Quartet(src_ip, dst_ip, src_port, dst_port))
    #     await self.mailbox.put(q)
    #
    # async def publish(self, event):
    #     q = ('publish', event)
    #     await self.mailbox.put(q)

    async def run(self):
        while True:
            event = await self.mailbox.get()
            if event.action == 'register':
                print('register {0}'.format(event.quartet))
                self.traces[str(event.quartet)] = []
            elif event.action == 'unregister':
                print('unregister {0}'.format(event.quartet))
                del self.traces[str(event.quartet)]
            elif event.action == 'publish':
                if str(event.quartet) in self.traces:
                    self.traces[str(event.quartet)].append(event.base_event)
                    print('publish {0}'.format(len(self.traces[str(event.quartet)])))
