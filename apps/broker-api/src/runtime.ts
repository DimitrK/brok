import type {Server} from 'node:http'

export const createDataPlaneRuntime = ({
  server,
  host,
  port
}: {
  server: Server
  host: string
  port: number
}) => {
  const start = async () =>
    new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(port, host, () => {
        server.off('error', reject)
        resolve()
      })
    })

  const stop = async () =>
    new Promise<void>(resolve => {
      server.close(() => resolve())
    })

  return {
    server,
    start,
    stop
  }
}
