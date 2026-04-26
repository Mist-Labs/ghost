import path from "path";
import { createRequire } from "module";
import { fileURLToPath, pathToFileURL } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspaceRoot = path.resolve(__dirname, "..");
const frontendRoot = path.join(workspaceRoot, "frontend");
const requireFromFrontend = createRequire(path.join(frontendRoot, "package.json"));

async function loadFrontendDependency(packageName) {
  const resolved = requireFromFrontend.resolve(packageName);
  return import(pathToFileURL(resolved).href);
}

async function main() {
  const [{ ZgFile, Indexer }, { ethers }] = await Promise.all([
    loadFrontendDependency("@0gfoundation/0g-ts-sdk"),
    loadFrontendDependency("ethers"),
  ]);

  const filePath = process.argv[2];
  const contentType = process.argv[3] || "application/octet-stream";
  const rpcUrl = process.env.ZG_RPC_URL;
  const indexerRpc = process.env.ZG_INDEXER_RPC;
  const privateKey = process.env.ZG_PRIVATE_KEY;

  if (!filePath) {
    throw new Error("usage: node scripts/publish_to_0g.mjs <file-path> [content-type]");
  }
  if (!rpcUrl || !indexerRpc || !privateKey) {
    throw new Error("ZG_RPC_URL, ZG_INDEXER_RPC, and ZG_PRIVATE_KEY are required");
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  const indexer = new Indexer(indexerRpc);
  const file = await ZgFile.fromFilePath(filePath);

  try {
    const [, treeErr] = await file.merkleTree();
    if (treeErr !== null) {
      throw new Error(`0G merkleTree error: ${treeErr}`);
    }

    const [tx, uploadErr] = await indexer.upload(file, rpcUrl, signer);
    if (uploadErr !== null) {
      throw new Error(`0G upload error: ${uploadErr}`);
    }

    const payload =
      "rootHash" in tx
        ? { root_hash: tx.rootHash, tx_hash: tx.txHash, content_type: contentType }
        : { root_hash: tx.rootHashes[0], tx_hash: tx.txHashes[0], content_type: contentType };

    process.stdout.write(JSON.stringify(payload));
  } finally {
    await file.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
