import { CIRCUIT_ASSETS, JWTCircuitInput } from "./constant";
import * as snarkjs from "snarkjs";

const IPFS_GATEWAYS = [
  "https://gateway.pinata.cloud/ipfs/",
  "https://4everland.io/ipfs/",
  "https://w3s.link/ipfs/",
  "https://dweb.link/ipfs/",
  "https://trustless-gateway.link/ipfs/",
  "https://nftstorage.link/ipfs/",
];

export async function fetchBinary(path: string): Promise<ArrayBuffer> {
  // If path is NOT an IPFS hash, just fetch normally
  if (!path.startsWith("bafybe")) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`Failed to fetch ${path}`);
    return await res.arrayBuffer();
  }

  // Otherwise, try fetching from multiple IPFS gateways
  for (const gateway of IPFS_GATEWAYS) {
    const url = `${gateway}${path}`;
    try {
      const res = await fetch(url);
      if (res.ok) {
        return await res.arrayBuffer();
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
      console.warn(`Fetch failed from ${url}, trying next...`);
    }
  }

  throw new Error(`Failed to fetch ${path} from all gateways`);
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
