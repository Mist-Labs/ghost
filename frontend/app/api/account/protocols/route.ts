import { requireSessionAccount } from "@/lib/server/auth";
import {
  createOperatorProtocol,
  validateOperatorProtocolInput,
  type OperatorProtocolInput,
} from "@/lib/server/operator-protocols";
import { upsertProtocolInRegistry } from "@/lib/server/protocol-registry-sync";
import { ensureTrustedOrigin } from "@/lib/server/request-security";

export async function POST(request: Request) {
  try {
    const originError = ensureTrustedOrigin(request);
    if (originError) {
      return originError;
    }

    const account = await requireSessionAccount();
    const body = (await request.json()) as OperatorProtocolInput;
    const validationError = validateOperatorProtocolInput(body);
    if (validationError) {
      return Response.json({ error: validationError }, { status: 400 });
    }

    const protocol = await createOperatorProtocol(account.id, body);
    await upsertProtocolInRegistry(protocol);
    return Response.json({ ok: true, protocol });
  } catch (error) {
    if ((error as { code?: string })?.code === "23505") {
      return Response.json(
        { error: "A protocol with that key already exists in this account." },
        { status: 409 },
      );
    }

    return Response.json(
      {
        error:
          error instanceof Error ? error.message : "Unable to create protocol.",
      },
      { status: 500 },
    );
  }
}
