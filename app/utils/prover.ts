import { CIRCUIT_ASSETS, JWTCircuitInput } from "./constant";
import * as snarkjs from "snarkjs";

export async function fetchBinary(path: string): Promise<ArrayBuffer> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to fetch ${path}`);
  return await res.arrayBuffer();
}
export class JwtProver {
  static async generateProof(input: JWTCircuitInput) {
    try {
      const wasm = new Uint8Array(await fetchBinary(CIRCUIT_ASSETS.WASM));
      const zkey = new Uint8Array(await fetchBinary(CIRCUIT_ASSETS.ZKEY));

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasm,
        zkey
      );

      return { proof, publicSignals };
    } catch (error) {
      console.error("Error generating proof:", error);
      throw error;
    }
  }

  static async verifyProof(
    proof: snarkjs.Groth16Proof,
    publicSignals: string[]
  ): Promise<boolean> {
    try {
      const vkeyRes = await fetch(CIRCUIT_ASSETS.VKEY);
      const vkey = await vkeyRes.json();

      return await snarkjs.groth16.verify(vkey, publicSignals, proof);
    } catch (error) {
      console.error("Error verifying proof:", error);
      throw error;
    }
  }
}
