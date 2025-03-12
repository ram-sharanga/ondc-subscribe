const nacl = require("tweetnacl");
const crypto = require("crypto");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

function generateKeyPairs() {
  const signingKeyPair = nacl.sign.keyPair();
  const { privateKey, publicKey } = crypto.generateKeyPairSync("x25519", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  return {
    request_id: uuidv4(),
    signing_private_key: Buffer.from(signingKeyPair.secretKey).toString(
      "base64"
    ),
    signing_public_key: Buffer.from(signingKeyPair.publicKey).toString(
      "base64"
    ),
    encryption_private_key: privateKey
      .toString("utf-8")
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\s/g, ""),
    encryption_public_key: publicKey
      .toString("utf-8")
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s/g, ""),
  };
}

const keyPairs = generateKeyPairs();

// Save keys to a .env file
const envContent = Object.entries(keyPairs)
  .map(([key, value]) => `${key}=${value}`)
  .join("\n");
fs.writeFileSync(".env", envContent);
console.log("Keys saved to .env");
