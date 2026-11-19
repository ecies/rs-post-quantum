// Payloads between ecies-post-quantum and @ecies/post-quantum, one per line: the config in its JS names, then the
// payload in hex. Every config encrypts "hello world" to the keys that `keygen(seed)` derives from the seed 0, 1, ..., 63.
//
//   node payloads.mjs encrypt          prints the payloads of @ecies/post-quantum, as in ../js_payloads.txt
//   node payloads.mjs decrypt <file>   decrypts the payloads of `cargo run --example rust_payloads`
import { readFileSync } from "node:fs";
import { Config, decrypt, encrypt } from "@ecies/post-quantum";

const SEED = Uint8Array.from({ length: 64 }, (_, i) => i);
const MESSAGE = "hello world";

function* configs() {
  for (const asymmetricAlgorithm of ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]) {
    for (const [symmetricAlgorithm, symmetricNonceLength] of [
      ["aes-256-gcm", 16],
      ["aes-256-gcm", 12],
      ["xchacha20", 16],
    ]) {
      const config = new Config();
      config.asymmetricAlgorithm = asymmetricAlgorithm;
      config.symmetricAlgorithm = symmetricAlgorithm;
      config.symmetricNonceLength = symmetricNonceLength;
      const names = `${asymmetricAlgorithm} ${symmetricAlgorithm} ${symmetricNonceLength}`;
      yield { names, config, keys: config.asymmetricModule.keygen(SEED) };
    }
  }
}

const [mode, file] = process.argv.slice(2);
if (mode === "encrypt") {
  for (const { names, config, keys } of configs()) {
    const payload = encrypt(keys.publicKey, new TextEncoder().encode(MESSAGE), config);
    console.log(`${names} ${Buffer.from(payload).toString("hex")}`);
  }
} else if (mode === "decrypt") {
  const lines = readFileSync(file, "utf8").split("\n");
  for (const { names, config, keys } of configs()) {
    const line = lines.find((line) => line.startsWith(`${names} `));
    if (line === undefined) throw new Error(`no payload for ${names}`);

    let decrypted;
    try {
      decrypted = decrypt(keys.secretKey, Buffer.from(line.slice(names.length + 1), "hex"), config);
    } catch (cause) {
      throw new Error(`${names}: decryption failed`, { cause });
    }
    const text = new TextDecoder().decode(decrypted);
    if (text !== MESSAGE) throw new Error(`${names}: decrypted ${JSON.stringify(text)}`);
    console.log(`${names} ok`);
  }
} else {
  throw new Error("usage: node payloads.mjs encrypt | node payloads.mjs decrypt <file>");
}
