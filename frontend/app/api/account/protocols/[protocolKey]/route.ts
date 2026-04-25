import { requireSessionAccount } from "@/lib/server/auth";
import {
  deleteOperatorProtocol,
  updateOperatorProtocol,
  validateOperatorProtocolInput,
  type OperatorProtocolInput,
} from "@/lib/server/operator-protocols";
import { ensureTrustedOrigin } from "@/lib/server/request-security";

type RouteContext = {
  params: {
    protocolKey: string;
  };
};

export async function PATCH(request: Request, context: RouteContext) {
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

    const protocol = await updateOperatorProtocol(
      account.id,
      context.params.protocolKey,
      body,
    );

    if (!protocol) {
      return Response.json({ error: "Protocol not found." }, { status: 404 });
    }

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
          error instanceof Error ? error.message : "Unable to update protocol.",
      },
      { status: 500 },
    );
  }
}

export async function DELETE(request: Request, context: RouteContext) {
  try {
    const originError = ensureTrustedOrigin(request);
    if (originError) {
      return originError;
    }

    const account = await requireSessionAccount();
    const deleted = await deleteOperatorProtocol(account.id, context.params.protocolKey);

    if (!deleted) {
      return Response.json({ error: "Protocol not found." }, { status: 404 });
    }

    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      {
        error:
          error instanceof Error ? error.message : "Unable to delete protocol.",
      },
      { status: 500 },
    );
  }
}
