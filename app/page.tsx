"use client";

import { useState } from "react";
import { sha256 } from "@noble/hashes/sha256";
import { base64url } from "jose";
import { verifyJWT } from "./utils/utils";
import { JwtProver } from "./utils/prover";
import * as snarkjs from "snarkjs";
import { generateInputs } from "./utils/generate_inputs";
import { JwkEcdsaPublicKey } from "./utils/es256";

export default function Home() {
  const [token, setToken] = useState("");
  const [claimsInput, setClaimsInput] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [proof, setProof] = useState<snarkjs.Groth16Proof | null>(null);
  const [signals, setSignals] = useState<string[] | null>(null);

  const [jwk, setJwk] = useState<JwkEcdsaPublicKey>({
    kty: "EC",
    crv: "P-256",
    x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
    y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
  });

  const [inputs, setInputs] = useState<any | null>(null);

  const handleValidate = async () => {
    try {
      if (!token) return setStatus("❌ Missing JWT Token");
      if (!claimsInput) return setStatus("❌ Missing Claims");

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

      const hashedClaims = claims.map((e) =>
        base64url.encode(sha256(e)).toString()
      );

      for (let i = 0; i < sd.length; i++) {
        if (sd[i] !== hashedClaims[i]) {
          return setStatus(`❌ Claim ${i + 1} hash mismatch`);
        }
      }

      setStatus("✅ Valid Signature + Claims Match");
    } catch (err) {
      if (err instanceof Error) setStatus(`❌ ${err.message}`);
      else setStatus("❌ Unknown error");
    }
  };

  const handleGenerateProof = async () => {
    try {
      if (!token) return setStatus("❌ Provide JWT first");

      setStatus("⏳ Generating circuit inputs...");
      const input = await generateInputs(token, jwk);
      console.log("Circuit Inputs:", input);
      console.log("Circuit Inputs:", input);

      // const inputs = JSON.stringify(
      //   input,
      //   (_, v) => (typeof v === "bigint" ? v.toString() : v),
      //   2
      // );
      // setInputs(input);

      setStatus("⏳ Generating proof...");
      // const { proof, publicSignals } = await JwtProver.generateProof(inputs);

      setProof(proof);
      // setSignals(publicSignals);
      setStatus("✅ Proof generated successfully");
    } catch (err) {
      console.error(err);
      setStatus("❌ Failed to generate proof");
    }
  };

  const handleVerifyProof = async () => {
    try {
      if (!proof || !signals) {
        return setStatus("❌ No proof or signals to verify");
      }

      setStatus("⏳ Verifying proof...");
      const isValid = await JwtProver.verifyProof(proof, signals);
      setStatus(
        isValid
          ? "✅ Proof verification succeeded"
          : "❌ Proof verification failed"
      );
    } catch (err) {
      console.error(err);
      setStatus("❌ Error during verification");
    }
  };

  return (
    <main className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-3xl mx-auto bg-white shadow p-6 rounded-xl space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Seediq JWT ZK Validator</h1>
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
            try {
              setJwk(JSON.parse(e.target.value));
            } catch {
              setStatus("❌ Invalid JWK JSON");
            }
          }}
          className="w-full border p-2 font-mono rounded"
          rows={6}
        />

        <div className="space-x-4">
          <button
            onClick={handleValidate}
            className="bg-black text-white px-6 py-2 rounded hover:bg-gray-800"
          >
            Validate JWT
          </button>

          <button
            onClick={handleGenerateProof}
            className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700"
          >
            Generate Proof
          </button>

          <button
            onClick={handleVerifyProof}
            className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700"
          >
            Verify Proof
          </button>
        </div>

        {status && (
          <p
            className={`text-lg mt-4 ${
              status.startsWith("✅")
                ? "text-green-600"
                : status.startsWith("⏳")
                ? "text-yellow-600"
                : "text-red-600"
            }`}
          >
            {status}
          </p>
        )}

        {inputs && (
          <div>
            <h2 className="text-lg font-semibold mt-4">Circuit Inputs</h2>
            <pre className="text-sm bg-gray-100 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(inputs, null, 2)}
            </pre>
          </div>
        )}

        {proof && (
          <div className="mt-6">
            <h2 className="text-lg font-semibold">Proof</h2>
            <pre className="text-sm bg-gray-100 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(proof, null, 2)}
            </pre>
          </div>
        )}

        {signals && (
          <div className="mt-6">
            <h2 className="text-lg font-semibold">Public Signals</h2>
            <pre className="text-sm bg-gray-100 p-4 rounded overflow-auto max-h-64">
              {JSON.stringify(signals, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </main>
  );
}
