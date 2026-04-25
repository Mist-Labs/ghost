import { clearSession } from "@/lib/server/auth";
import { ensureTrustedOrigin } from "@/lib/server/request-security";

export async function POST(request: Request) {
  try {
    const originError = ensureTrustedOrigin(request);
    if (originError) {
      return originError;
    }

    await clearSession();
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : "Unable to sign out." },
      { status: 500 },
    );
  }
}
