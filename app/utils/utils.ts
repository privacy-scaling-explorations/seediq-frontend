export async function verifyJWT(
  token: string,
  jwk: JsonWebKey
): Promise<boolean> {
  const [header, payload, signature] = token.split(".");
  const data = new TextEncoder().encode(`${header}.${payload}`);
  const sigBytes = Uint8Array.from(
    atob(signature.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    sigBytes,
    data
  );
}

export async function readFileAsBuffer(path: string): Promise<ArrayBuffer> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to fetch ${path}`);
  return await res.arrayBuffer();
}

export function sha256Pad(
  message: Uint8Array,
  maxMessageLength: number
): [Uint8Array, number] {
  const messageBitLength = message.length * 8;

  // Calculate required padding
  const totalLength = message.length + 1 + 8; // 0x80 + 64-bit length
  const mod = totalLength % 64;
  const padLength = mod === 0 ? 0 : 64 - mod;

  const finalLength = message.length + 1 + padLength + 8;

  if (finalLength > maxMessageLength) {
    throw new Error(
      `Message too long. Got padded length ${finalLength}, but max allowed is ${maxMessageLength}`
    );
  }

  const padded = new Uint8Array(maxMessageLength);
  padded.set(message, 0);
  padded[message.length] = 0x80;

  // Write 64-bit big-endian length (in bits) at the end
  const bitLen = messageBitLength;
  for (let i = 0; i < 8; i++) {
    padded[finalLength - 8 + i] = (bitLen >>> ((7 - i) * 8)) & 0xff;
  }

  return [padded, finalLength];
}
