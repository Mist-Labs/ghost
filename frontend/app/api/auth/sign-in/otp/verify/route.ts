import { createSession, findAccountByEmail } from "@/lib/server/auth";
import { consumeLoginOtp } from "@/lib/server/otp";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

const OTP_SESSION_DURATION_MS = 1000 * 60 * 60 * 24;

type OtpVerifyPayload = {
  email?: string;
  code?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as OtpVerifyPayload;
    const email = body.email?.trim().toLowerCase() ?? "";
    const code = body.code?.trim() ?? "";
    if (!email || code.length !== 6) {
      return Response.json(
        { error: "Invalid or expired OTP code." },
        { status: 401 },
      );
    }

    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:otp-verify", email),
      10,
      1000 * 60 * 15,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many verification attempts.");
    }

    const account = await findAccountByEmail(email);
    const verified = account ? await consumeLoginOtp(account.id, code) : false;
    if (!verified) {
      return Response.json({ error: "Invalid or expired OTP code." }, { status: 401 });
    }

    await createSession(account!.id, { durationMs: OTP_SESSION_DURATION_MS });
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: "Unable to verify OTP." },
      { status: 500 },
    );
  }
}
