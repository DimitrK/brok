import tls, {type TLSSocket} from 'tls';

const startServer = ({
  options,
  onConnection
}: {
  options: tls.TlsOptions;
  onConnection: (socket: TLSSocket) => void;
}) =>
  new Promise<tls.Server>((resolve, reject) => {
    const server = tls.createServer(options, socket => onConnection(socket));
    server.once('error', reject);
    server.listen(0, () => resolve(server));
  });

export const createTlsHarness = async ({
  options,
  onConnection
}: {
  options: tls.TlsOptions;
  onConnection: (socket: TLSSocket) => void;
}) => {
  const server = await startServer({options, onConnection});
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;

  return {
    port,
    close: () => new Promise<void>(resolve => server.close(() => resolve()))
  };
};
