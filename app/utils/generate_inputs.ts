import { JwkEcdsaPublicKey, PemPublicKey } from "./es256";
import { generateJwtCircuitParams, generateJwtInputs } from "./jwt";
// import { generateJwtCircuitParams, generateJwtInputs } from "./jwt";

export async function generateInputs(
  jwtToken: string,
  publicKey: JwkEcdsaPublicKey | PemPublicKey
) {
  const [header, payload, signature] = jwtToken.split(".");
  if (!header || !payload || !signature) throw new Error("Invalid JWT format");
  // console.log(jwtToken);
  // console.log(publicKey);

  // const params = generateEs256CircuitParams([43, 6, 1024]);
  // const pk = `-----BEGIN PUBLIC KEY-----
  // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
  // /cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
  // -----END PUBLIC KEY-----`;
  // const inputs = generateES256Inputs(
  //   params,
  //   Buffer.from(`${header}.${payload}`),
  //   signature,
  //   {
  //     pem: pk,
  //   }
  // );

  const params1 = generateJwtCircuitParams([43, 6, 1024, 256, 256, 5, 8]);
  const inputs1 = generateJwtInputs(params1, jwtToken, publicKey, [
    "ipxa",
    `"iat"`,
  ]);

  return inputs1;
}
