const express = require("express");
const path = require("path");
const crypto = require("crypto");
const _sodium = require("libsodium-wrappers");
require("dotenv").config();

const port = 3000;
const REQUEST_ID = process.env.request_id;
const SIGNING_PRIVATE_KEY = process.env.signing_private_key;
const ENCRYPTION_PRIVATE_KEY = process.env.encryption_private_key;
const ONDC_PUBLIC_KEY =
  "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=";

const htmlFile = `
  <!--Contents of ondc-site-verification.html. -->
  <!--Please replace SIGNED_UNIQUE_REQ_ID with an actual value-->
  <html>
    <head>
      <meta
        name="ondc-site-verification"
        content="SIGNED_UNIQUE_REQ_ID"
      />
    </head>
    <body>
      ONDC Site Verification Page
    </body>
  </html>
  `;

const privateKey = crypto.createPrivateKey({
  key: Buffer.from(ENCRYPTION_PRIVATE_KEY, "base64"),
  format: "der",
  type: "pkcs8",
});
const publicKey = crypto.createPublicKey({
  key: Buffer.from(ONDC_PUBLIC_KEY, "base64"),
  format: "der",
  type: "spki",
});
const sharedKey = crypto.diffieHellman({ privateKey, publicKey });

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Route for handling subscription requests
app.post("/solve_challenge/on_subscribe", function (req, res) {
  const { challenge } = req.body;
  const answer = decryptAES256ECB(sharedKey, challenge);
  const resp = { answer: answer };
  res.status(200).json(resp);
});

// Route for serving the verification file
app.get("/ondc-site-verification.html", async (req, res) => {
  console.log("ondc-site-verification.html triggered");
  const signedContent = await signMessage(REQUEST_ID, SIGNING_PRIVATE_KEY);
  const modifiedHTML = htmlFile.replace(/SIGNED_UNIQUE_REQ_ID/g, signedContent);
  res.send(modifiedHTML);
});

// Default route
app.get("/", (req, res) => {
  console.log("home route triggered");
  res.sendFile(path.join(__dirname, "/index.html"));
});

// Health check route
app.get("/health", (req, res) => res.send("Health OK!!"));

app.listen(port, () => console.log(`Example app listening on port ${port}!`));

// Decrypt using AES-256-ECB
function decryptAES256ECB(key, encrypted) {
  const iv = Buffer.alloc(0);
  const decipher = crypto.createDecipheriv("aes-256-ecb", key, iv);
  let decrypted = decipher.update(encrypted, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

async function signMessage(requestID, signingPrivateKey) {
  await _sodium.ready;
  const sodium = _sodium;

  // Convert requestID to Uint8Array before signing
  const requestIDBytes = sodium.from_string(requestID);
  const signedMessage = sodium.crypto_sign_detached(
    requestIDBytes,
    sodium.from_base64(signingPrivateKey, sodium.base64_variants.ORIGINAL)
  );

  return sodium.to_base64(signedMessage, sodium.base64_variants.ORIGINAL);
}
