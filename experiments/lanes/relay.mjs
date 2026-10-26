// A TCP relay that delays each chunk by half `--rtt` either way: Postgres as
// a database further away serves it. Bytes pass through untouched, TLS too.
//
//   node experiments/lanes/relay.mjs --listen 127.0.0.1:30195 --to 127.0.0.1:30194 --rtt 20
import { connect, createServer } from 'node:net';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: { listen: { type: 'string' }, to: { type: 'string' }, rtt: { type: 'string', default: '0' } } });
const [listenHost, listenPort] = values.listen.split(/:(?=\d+$)/);
const [toHost, toPort] = values.to.split(/:(?=\d+$)/);
const half = Number(values.rtt) / 2;

const server = createServer((client) => {
  client.setNoDelay(true);
  const upstream = connect(Number(toPort), toHost);
  upstream.setNoDelay(true);
  const relay = (from, into) => from.on('data', (chunk) => (half > 0 ? setTimeout(() => into.write(chunk), half) : into.write(chunk)));
  relay(client, upstream);
  relay(upstream, client);
  const end = () => {
    client.destroy();
    upstream.destroy();
  };
  client.on('close', end).on('error', end);
  upstream.on('close', end).on('error', end);
});
server.listen(Number(listenPort), listenHost, () => console.log(`relay ${values.listen} -> ${values.to}, ${values.rtt} ms`));
