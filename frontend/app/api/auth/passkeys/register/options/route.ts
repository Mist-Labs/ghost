import { getOptionalSessionAccount } from "@/lib/server/auth";
import { createRegistrationOptions } from "@/lib/server/passkeys";
import { ensureTrustedOrigin } from "@/lib/server/request-security";

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
    const options = await createRegistrationOptions(request, account);
    return Response.json(options);
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : "Unable to create passkey options." },
      { status: 500 },
    );
  }
}
