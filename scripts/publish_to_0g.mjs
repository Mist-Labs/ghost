import { ZgFile, Indexer } from "@0gfoundation/0g-ts-sdk";
import { ethers } from "ethers";

async function main() {
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
