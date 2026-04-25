import { createSession, findAccountByEmail } from "@/lib/server/auth";
import { verifyPassword } from "@/lib/server/passwords";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type SignInPayload = {
  email?: string;
  password?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as SignInPayload;
    const email = body.email?.trim().toLowerCase() ?? "";
    const password = body.password ?? "";
    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:password", email || "unknown"),
      10,
      1000 * 60 * 15,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many sign-in attempts.");
    }

    const account = await findAccountByEmail(email);
    if (!account || !(await verifyPassword(password, account.password_hash))) {
      return Response.json({ error: "Invalid email or password." }, { status: 401 });
    }

    await createSession(account.id);
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: "Unable to sign in." },
      { status: 500 },
    );
  }
}
