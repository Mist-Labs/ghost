import { createOperatorAccount, findAccountByEmail, createSession } from "@/lib/server/auth";
import { hashPassword, validatePassword } from "@/lib/server/passwords";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type SignUpPayload = {
  companyName?: string;
  contactName?: string;
  email?: string;
  password?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as SignUpPayload;
    const companyName = body.companyName?.trim() ?? "";
    const contactName = body.contactName?.trim() ?? "";
    const email = body.email?.trim().toLowerCase() ?? "";
    const password = body.password ?? "";
    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:sign-up", email || "unknown"),
      5,
      1000 * 60 * 60,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many sign-up attempts.");
    }

    if (!companyName) {
      return Response.json({ error: "Company name is required." }, { status: 400 });
    }

    if (!contactName) {
      return Response.json({ error: "Contact name is required." }, { status: 400 });
    }

    if (!email || !email.includes("@")) {
      return Response.json({ error: "A valid work email is required." }, { status: 400 });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return Response.json({ error: passwordError }, { status: 400 });
    }

    const existing = await findAccountByEmail(email);
    if (existing) {
      return Response.json({ error: "An account already exists for that email." }, { status: 409 });
    }

    const passwordHash = await hashPassword(password);
    const account = await createOperatorAccount({
      companyName,
      contactName,
      email,
      passwordHash,
    });

    await createSession(account.id);

    return Response.json({
      ok: true,
      account: {
        id: account.id,
        companyName: account.company_name,
        contactName: account.contact_name,
        email: account.email,
      },
    });
  } catch (error) {
    if ((error as { code?: string })?.code === "23505") {
      return Response.json({ error: "An account already exists for that email." }, { status: 409 });
    }

    return Response.json(
      { error: error instanceof Error ? error.message : "Unable to create account." },
      { status: 500 },
    );
  }
}
