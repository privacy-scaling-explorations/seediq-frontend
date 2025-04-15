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
