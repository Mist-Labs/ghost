import { createAuthenticationOptions } from "@/lib/server/passkeys";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type AuthOptionsPayload = {
  email?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as AuthOptionsPayload;
    const email = body.email?.trim().toLowerCase() ?? "";
    if (!email) {
      return Response.json({ error: "Email is required for passkey sign-in." }, { status: 400 });
    }

    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:passkey-options", email),
      10,
      1000 * 60 * 15,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many sign-in attempts.");
    }

    const options = await createAuthenticationOptions(request, email);
    return Response.json(options);
  } catch (error) {
    return Response.json(
      { error: "Unable to start passkey sign-in." },
      { status: 400 },
    );
  }
}
