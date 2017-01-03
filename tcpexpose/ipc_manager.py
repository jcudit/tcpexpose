import asyncio

from utils import Event, Quartet


# TODO: Remove print statements
class IPCManager(object):

    def __init__(self, loop):
        self.traces = {}
        self.mailbox = asyncio.Queue(maxsize=0, loop=loop)
        coro = loop.create_unix_server(lambda: IPCProtocol(self.mailbox),
                                       '/var/run/tcpexpose.sock')
        self.server = loop.run_until_complete(coro)

    async def run(self):
        while True:
            event = await self.mailbox.get()
            if event.action == 'register':
                self.traces[str(event.quartet)] = []
                print('register')
                print(self.traces.keys())
            elif event.action == 'unregister':
                print('unregister {0}'.format(event.quartet))
                try:
                    del self.traces[str(event.quartet)]
                except KeyError:
                    pass
            elif event.action == 'publish':
                if str(event.quartet) in self.traces:
                    try:
                        self.traces[str(event.quartet)].append(event.json)
                        print('publish {0}'.format(
                            len(self.traces[str(event.quartet)])))
                    except KeyError:
                        pass
            elif event.action == 'flush':
                print('flushing {0}'.format(str(event.quartet)))
                print(self.traces.keys())
                try:
                    if str(event.quartet) in self.traces:
                        quartets = [str(event.quartet), event.quartet.revstr()]
                        for quartet in quartets:
                            while len(self.traces[quartet]) != 0:
                                json_event = self.traces[quartet].pop(0)
                                event.transport.write(json_event.encode())
                                event.transport.write('\n'.encode())
                except KeyError:
                    # TODO: Increment something
                    pass


class IPCProtocol(asyncio.Protocol):
    def __init__(self, mailbox):
        self.ipc_manager_mailbox = mailbox

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))
        quartet = self._parse_quartet(message)

        if quartet is not None:
            event = Event()
            event.action = 'flush'
            event.quartet = quartet
            event.transport = self.transport

            try:
                self.ipc_manager_mailbox.put_nowait(event)
            except QueueEmpty:
                # TODO: Increment metric
                pass

    def eof_received(self):
        print('Close the client socket')
        self.transport.close()

    def _parse_quartet(self, message):
        splits = message.split()
        if len(splits) < 4:
            return None
        return Quartet(splits[0], splits[1], splits[2], splits[3])
