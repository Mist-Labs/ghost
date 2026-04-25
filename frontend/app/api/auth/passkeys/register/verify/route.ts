import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { getOptionalSessionAccount } from "@/lib/server/auth";
import { verifyRegistration } from "@/lib/server/passkeys";
import { ensureTrustedOrigin } from "@/lib/server/request-security";

type VerifyPayload = {
  response?: RegistrationResponseJSON;
};

export async function POST(request: Request) {
  try {
    const originError = ensureTrustedOrigin(request);
    if (originError) {
      return originError;
    }

    const account = await getOptionalSessionAccount();
    if (!account) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = (await request.json()) as VerifyPayload;
    if (!body.response) {
      return Response.json({ error: "Passkey response is required." }, { status: 400 });
    }

    await verifyRegistration(body.response);
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : "Unable to verify passkey registration." },
      { status: 500 },
    );
  }
}
