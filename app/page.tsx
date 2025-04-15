"use client";

import { useState } from "react";
import { sha256 } from "@noble/hashes/sha256";
import { base64url } from "jose";
import { verifyJWT } from "./utils/utils";

export default function Home() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  const [jwk, setJwk] = useState<JsonWebKey>({
    kty: "EC",
    crv: "P-256",
    x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
    y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
  });

  const handleVerify = async () => {
    try {
      if (token === "") return setStatus("❌ Missing JWT Token");
      if (claimsInput === "") return setStatus("❌ Missing Claims");

      const isValid = await verifyJWT(token, jwk);
      if (!isValid) return setStatus("❌ Signature Invalid");

      const payload = JSON.parse(atob(token.split(".")[1]));
      const sd = payload?.vc?.credentialSubject?._sd;
      if (!sd || !Array.isArray(sd))
        return setStatus("✅ Valid Signature (no hashed claims)");

      const claims = claimsInput
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      const hashedClaims = claims.map((e) => {
        return base64url.encode(sha256(e)).toString();
      });

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

        <div className="flex items-center justify-between">
          <a
            href="https://github.com/adria0/seediq-playground"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-blue-600 hover:underline"
          >
            GitHub ↗
          </a>
        </div>
        <textarea
          placeholder="JWT Token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full border p-2 rounded"
          rows={4}
        />

        <textarea
          placeholder="Raw Claims (one per line)"
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
