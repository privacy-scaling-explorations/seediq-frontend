"use client";

import { useState } from "react";

async function verifyJWT(token: string, jwk: JsonWebKey): Promise<boolean> {
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

export default function Home() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  const [jwk, setJwk] = useState<JsonWebKey>({
    kty: "EC",
    crv: "P-256",
    // kid: "key-1",
    x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
    y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
  });

  const handleVerify = async () => {
    try {
      const isValid = await verifyJWT(token, jwk);
      if (!isValid) return setStatus("❌ Signature Invalid");

      const payload = JSON.parse(atob(token.split(".")[1]));
      const sd = payload?.vc?.credentialSubject?._sd;
      if (!sd || !Array.isArray(sd))
        return setStatus("✅ Valid Signature (no hashed claims)");

      const hashedClaims = claimsInput
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      for (let i = 0; i < sd.length; i++) {
        if (sd[i] !== hashedClaims[i]) {
          return setStatus(`❌ Claim ${i + 1} hash mismatch`);
        }
      }

      setStatus("✅ Valid Signature + Claims Match");
    } catch (err) {
      if (err instanceof Error) {
        setStatus(`❌ Error: ${err.message}`);
      } else {
        setStatus("❌ An unknown error occurred");
      }
    }
  };

  return (
    <main className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-3xl mx-auto bg-white shadow p-6 rounded-xl space-y-6">
        <h1 className="text-2xl font-bold">Seediq JWT Validator</h1>

        <textarea
          placeholder="JWT Token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full border p-2 rounded"
          rows={4}
        />

        <textarea
          placeholder="Claims (one per line)"
          value={claimsInput}
          onChange={(e) => setClaimsInput(e.target.value)}
          className="w-full border p-2 rounded"
          rows={3}
        />

        <textarea
          placeholder="JWK"
          value={JSON.stringify(jwk, null, 2)}
          onChange={(e) => {
            setJwk(JSON.parse(e.target.value));
          }}
          className="w-full border p-2 font-mono rounded"
          rows={6}
        />

        <button
          onClick={handleVerify}
          className="bg-black text-white px-6 py-2 rounded hover:bg-gray-800"
        >
          Verify
        </button>

        {status && <p className="text-lg mt-4">{status}</p>}
      </div>
    </main>
  );
}
