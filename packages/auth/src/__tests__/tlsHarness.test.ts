import {EventEmitter} from 'events';
import tls, {type TLSSocket} from 'tls';

import {describe, expect, it, vi} from 'vitest';

import {createTlsHarness} from '../tlsHarness';

type MockServer = EventEmitter & {
  listen: (port: number, callback: () => void) => void;
  address: () => {port: number; address: string; family: string} | null;
  close: (callback: () => void) => void;
};

const createMockServer = ({port, failOnListen}: {port: number; failOnListen?: boolean}) => {
  const server = new EventEmitter() as MockServer;
  server.listen = (_port, callback) => {
    if (failOnListen) {
      server.emit('error', new Error('listen-failed'));
      return;
    }

    callback();
  };
  server.address = () => ({port, address: '127.0.0.1', family: 'IPv4'});
  server.close = callback => {
    callback();
  };
  return server;
};

describe('tlsHarness', () => {
  it('returns listening port and delegates close', async () => {
    const onConnection = vi.fn();
    const createServer = vi.spyOn(tls, 'createServer').mockImplementation((_options, handler) => {
      const server = createMockServer({port: 4444});
      handler?.({id: 'socket-1'} as unknown as TLSSocket);
      return server as unknown as tls.Server;
    });

    const harness = await createTlsHarness({
      options: {},
      onConnection
    });

    expect(createServer).toHaveBeenCalled();
    expect(onConnection).toHaveBeenCalledTimes(1);
    expect(harness.port).toBe(4444);

    await harness.close();

    createServer.mockRestore();
  });

  it('rejects when the TLS server emits an error before listening', async () => {
    const createServer = vi
      .spyOn(tls, 'createServer')
      .mockImplementation(() => createMockServer({port: 0, failOnListen: true}) as unknown as tls.Server);

    await expect(
      createTlsHarness({
        options: {},
        onConnection: () => {}
      })
    ).rejects.toThrow('listen-failed');

    createServer.mockRestore();
  });
});
