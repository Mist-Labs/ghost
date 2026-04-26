import fs from "fs/promises";
import path from "path";
import type { ProtocolDefinition } from "@/lib/protocols";

function protocolRegistryFileName() {
  return process.env.PROTOCOLS_FILE || "protocols.base-sepolia.example.json";
}

async function resolveRegistryPath() {
  const fileName = protocolRegistryFileName();
  if (path.isAbsolute(fileName)) {
    return fileName;
  }

  const candidates = [
    path.join(process.cwd(), fileName),
    path.join(path.resolve(process.cwd(), ".."), fileName),
  ];

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Try the next path.
    }
  }

  return candidates[candidates.length - 1];
}

async function readRegistryProtocols(registryPath: string) {
  try {
    const raw = await fs.readFile(registryPath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ProtocolDefinition[]) : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

async function writeRegistryProtocols(
  registryPath: string,
  protocols: ProtocolDefinition[],
) {
  await fs.mkdir(path.dirname(registryPath), { recursive: true });
  await fs.writeFile(`${registryPath}.tmp`, `${JSON.stringify(protocols, null, 2)}\n`, "utf8");
  await fs.rename(`${registryPath}.tmp`, registryPath);
}

export async function upsertProtocolInRegistry(protocol: ProtocolDefinition) {
  const registryPath = await resolveRegistryPath();
  const protocols = await readRegistryProtocols(registryPath);
  const nextProtocols = [
    protocol,
    ...protocols.filter((entry) => entry.id !== protocol.id),
  ];

  await writeRegistryProtocols(registryPath, nextProtocols);
}

export async function deleteProtocolFromRegistry(protocolId: string) {
  const registryPath = await resolveRegistryPath();
  const protocols = await readRegistryProtocols(registryPath);
  const nextProtocols = protocols.filter((entry) => entry.id !== protocolId);

  await writeRegistryProtocols(registryPath, nextProtocols);
}
