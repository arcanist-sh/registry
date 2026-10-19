import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { webcrypto } from "node:crypto";
import { defineConfig } from "vitest/config";

// A throwaway online TUF key for the test Worker (the real one is a secret).
const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const onlineJwk = await webcrypto.subtle.exportKey("jwk", pair.privateKey);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ADMIN_TOKEN: "test-admin-token",
          TUF_ONLINE_KEY: JSON.stringify(onlineJwk),
          HACKAGE_RESERVATION: "off",
          PUBLIC_URL: "https://registry.test",
          TEST_MIGRATIONS: await readD1Migrations("./migrations"),
        },
      },
    }),
  ],
  test: {
    setupFiles: ["./test/apply-migrations.ts"],
  },
});
