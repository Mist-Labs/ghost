#!/usr/bin/env node

import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, "..");
const workspaceRoot = path.resolve(frontendRoot, "..");
const contractsRoot = path.join(workspaceRoot, "contracts");

function loadRootEnv() {
  const envPath = path.join(workspaceRoot, ".env");
  if (!fs.existsSync(envPath)) {
    return;
  }

  const raw = fs.readFileSync(envPath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) {
      continue;
    }

    const [, key, rawValue] = match;
    if (process.env[key] !== undefined) {
      continue;
    }

    let value = rawValue.trim();
    if (
      (value.startsWith("\"") && value.endsWith("\"")) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }

    process.env[key] = value;
  }
}

function bridgeFoundryEnv() {
  if (process.env.ALCHEMY_HTTP_URL && !process.env.ETH_RPC_URL) {
    process.env.ETH_RPC_URL = process.env.ALCHEMY_HTTP_URL;
  }

  if (process.env.BASESCAN_API_KEY) {
    if (!process.env.ETHERSCAN_API_KEY) {
      process.env.ETHERSCAN_API_KEY = process.env.BASESCAN_API_KEY;
    }
    if (!process.env.VERIFIER_API_KEY) {
      process.env.VERIFIER_API_KEY = process.env.BASESCAN_API_KEY;
    }
  }

  if (process.env.EXPLORER_API_URL && !process.env.VERIFIER_URL) {
    process.env.VERIFIER_URL = process.env.EXPLORER_API_URL;
  }

  if (process.env.CHAIN_ID && !process.env.CHAIN) {
    process.env.CHAIN = process.env.CHAIN_ID;
  }
}

loadRootEnv();
bridgeFoundryEnv();

const args = process.argv.slice(2);

if (args.length === 0) {
  console.error("usage: node ./scripts/run-foundry.mjs <forge args...>");
  process.exit(1);
}

const child = spawn("forge", args, {
  cwd: contractsRoot,
  stdio: "inherit",
  env: process.env,
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});

