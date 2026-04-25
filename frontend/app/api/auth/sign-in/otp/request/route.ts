import { findAccountByEmail } from "@/lib/server/auth";
import { issueLoginOtp } from "@/lib/server/otp";
import {
  consumeRateLimit,
  rateLimitKey,
  rateLimitResponse,
} from "@/lib/server/rate-limit";

type OtpRequestPayload = {
  email?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as OtpRequestPayload;
    const email = body.email?.trim().toLowerCase() ?? "";
    if (!email) {
      return Response.json({ error: "Email is required." }, { status: 400 });
    }

    const limit = consumeRateLimit(
      rateLimitKey(request, "auth:otp-request", email),
      5,
      1000 * 60 * 15,
    );
    if (!limit.allowed) {
      return rateLimitResponse(limit.retryAfterMs, "Too many OTP requests.");
    }

    const account = await findAccountByEmail(email);
    if (account?.otp_enabled) {
      await issueLoginOtp(account);
    }

    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: "Unable to send OTP." },
      { status: 500 },
    );
  }
}
