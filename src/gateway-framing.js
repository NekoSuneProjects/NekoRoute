// Buffered SOCKS/HTTP handshake reader. TCP is a byte stream, not message framed.
export async function readExact(socket, length) {
  if (!Number.isInteger(length) || length < 0 || length > 65536) throw new Error('Invalid handshake length');
  if (length === 0) return Buffer.alloc(0);
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.off('readable', check);
      socket.off('error', fail);
      socket.off('end', ended);
      socket.off('close', ended);
      socket.off('timeout', timedOut);
    };
    const fail = error => { cleanup(); reject(error); };
    const ended = () => fail(new Error('Connection closed during proxy handshake'));
    const timedOut = () => fail(new Error('Proxy handshake timed out'));
    const check = () => {
      const value = socket.read(length);
      if (value !== null) { cleanup(); resolve(value); }
      else if (socket.destroyed || socket.readableEnded) ended();
    };
    socket.on('readable', check);
    socket.once('error', fail);
    socket.once('end', ended);
    socket.once('close', ended);
    socket.once('timeout', timedOut);
    check();
  });
}

export async function readHttpHeaders(socket, maxBytes = 32768) {
  const bytes = [];
  while (bytes.length < maxBytes) {
    const byte = await readExact(socket, 1);
    bytes.push(byte[0]);
    const n = bytes.length;
    if (n >= 4 && bytes[n-4] === 13 && bytes[n-3] === 10 && bytes[n-2] === 13 && bytes[n-1] === 10) {
      return Buffer.from(bytes);
    }
  }
  throw new Error('Upstream CONNECT response too large');
}

export async function readSocksAddress(socket, addressType) {
  if (addressType === 1) return readExact(socket, 4);
  if (addressType === 4) return readExact(socket, 16);
  if (addressType === 3) {
    const length = (await readExact(socket, 1))[0];
    return readExact(socket, length);
  }
  throw new Error('Invalid SOCKS5 address type');
}
