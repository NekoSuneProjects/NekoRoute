import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readExact, readHttpHeaders, readSocksAddress } from '../src/gateway-framing.js';

async function pair() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const accepted = new Promise(resolve => server.once('connection', resolve));
  const client = net.connect(server.address().port, '127.0.0.1');
  await new Promise(resolve => client.once('connect', resolve));
  const peer = await accepted;
  return {client, peer, server, close() { client.destroy(); peer.destroy(); server.close(); }};
}

test('reads fragmented TCP handshake as exact-length frames', async () => {
  const p = await pair();
  try {
    const read = readExact(p.peer, 4);
    p.client.write(Buffer.from([5, 0]));
    setImmediate(() => p.client.write(Buffer.from([0, 1, 127, 0, 0, 1])));
    assert.deepEqual(await read, Buffer.from([5, 0, 0, 1]));
    assert.deepEqual(await readExact(p.peer, 4), Buffer.from([127, 0, 0, 1]));
  } finally { p.close(); }
});

test('CONNECT header reader preserves bytes following the header', async () => {
  const p = await pair();
  try {
    const pending = readHttpHeaders(p.peer);
    p.client.write('HTTP/1.1 200 Connection Established\r\n\r\nHELLO');
    assert.equal((await pending).toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
    assert.equal((await readExact(p.peer, 5)).toString(), 'HELLO');
  } finally { p.close(); }
});

test('SOCKS5 reply consumes variable-length bound address', async () => {
  const p = await pair();
  try {
    const pending = readSocksAddress(p.peer, 3);
    p.client.write(Buffer.from([4, 116, 101, 115, 116, 0, 80]));
    assert.equal((await pending).toString(), 'test');
    assert.deepEqual(await readExact(p.peer, 2), Buffer.from([0, 80]));
  } finally { p.close(); }
});

test('rejects closed handshakes instead of hanging', async () => {
  const p = await pair();
  try {
    const pending = readExact(p.peer, 3);
    p.client.end();
    await assert.rejects(pending, /closed|ended/i);
  } finally { p.close(); }
});
