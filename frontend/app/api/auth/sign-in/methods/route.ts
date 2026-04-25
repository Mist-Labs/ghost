import { countPasskeysForAccount, findAccountByEmail } from "@/lib/server/auth";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type SignInMethodsPayload = {
  email?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as SignInMethodsPayload;
    const email = body.email?.trim().toLowerCase() ?? "";
    if (!email) {
      return Response.json({ error: "Email is required." }, { status: 400 });
    }

    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:methods", email),
      20,
      1000 * 60 * 5,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many sign-in attempts.");
    }

    const account = await findAccountByEmail(email);
    const passkeyCount = account ? await countPasskeysForAccount(account.id) : 0;

    return Response.json({
      hasPasskey: passkeyCount > 0,
    });
  } catch (error) {
    return Response.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Unable to inspect sign-in methods.",
      },
      { status: 500 },
    );
  }
}
