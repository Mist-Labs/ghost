import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { createSession } from "@/lib/server/auth";
import { verifyAuthentication } from "@/lib/server/passkeys";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type VerifyPayload = {
  response?: AuthenticationResponseJSON;
};

export async function POST(request: Request) {
  try {
    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:passkey-verify"),
      10,
      1000 * 60 * 15,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many sign-in attempts.");
    }

    const body = (await request.json()) as VerifyPayload;
    if (!body.response) {
      return Response.json({ error: "Passkey response is required." }, { status: 400 });
    }

    const accountId = await verifyAuthentication(body.response);
    await createSession(accountId);
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: "Unable to verify passkey sign-in." },
      { status: 400 },
    );
  }
}
