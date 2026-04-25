import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import { cookies } from "next/headers";
import {
  findAccountByEmail,
  findPasskeyByCredentialId,
  listPasskeysForAccount,
  storePasskey,
  updatePasskeyCounter,
  type OperatorAccount,
} from "@/lib/server/auth";

const REGISTER_COOKIE = "ghost_webauthn_register";
const AUTH_COOKIE = "ghost_webauthn_auth";
const COOKIE_TTL_MS = 1000 * 60 * 5;

type ChallengeState = {
  accountId: string;
  challenge: string;
  origin: string;
  rpID: string;
  expiresAt: number;
};

export async function createRegistrationOptions(
  request: Request,
  account: OperatorAccount,
) {
  const { origin, rpID } = getRpConfig(request);
  const existingPasskeys = await listPasskeysForAccount(account.id);
  const options = await generateRegistrationOptions({
    rpName: "Ghost",
    rpID,
    userName: account.email,
    userDisplayName: `${account.company_name} · ${account.contact_name}`,
    userID: isoUint8Array.fromUTF8String(account.webauthn_user_id),
    excludeCredentials: existingPasskeys.map((passkey) => ({
      id: passkey.credential_id,
      transports: passkey.transports as AuthenticatorTransportFuture[],
    })),
  });

  setChallengeCookie(REGISTER_COOKIE, {
    accountId: account.id,
    challenge: options.challenge,
    origin,
    rpID,
    expiresAt: Date.now() + COOKIE_TTL_MS,
  });

  return options;
}

export async function verifyRegistration(
  response: RegistrationResponseJSON,
) {
  const challenge = getChallengeCookie(REGISTER_COOKIE);
  if (!challenge) {
    throw new Error("Registration session expired. Please try again.");
  }

  const verified = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: challenge.origin,
    expectedRPID: challenge.rpID,
  });

  if (!verified.verified) {
    throw new Error("Passkey registration could not be verified.");
  }

  const credential = verified.registrationInfo.credential;
  await storePasskey({
    accountId: challenge.accountId,
    credentialId: credential.id,
    publicKey: isoBase64URL.fromBuffer(credential.publicKey),
    counter: credential.counter,
    transports: (response.response.transports ?? []) as string[],
    deviceType: verified.registrationInfo.credentialDeviceType,
    backedUp: verified.registrationInfo.credentialBackedUp,
  });

  cookies().delete(REGISTER_COOKIE);
}

export async function createAuthenticationOptions(
  request: Request,
  email: string,
) {
  const account = await findAccountByEmail(email);
  if (!account) {
    throw new Error("No account found for that email.");
  }

  const passkeys = await listPasskeysForAccount(account.id);
  if (!passkeys.length) {
    throw new Error("No passkeys are configured for that account yet.");
  }

  const { origin, rpID } = getRpConfig(request);
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.credential_id,
      transports: passkey.transports as AuthenticatorTransportFuture[],
    })),
    userVerification: "preferred",
  });

  setChallengeCookie(AUTH_COOKIE, {
    accountId: account.id,
    challenge: options.challenge,
    origin,
    rpID,
    expiresAt: Date.now() + COOKIE_TTL_MS,
  });

  return options;
}

export async function verifyAuthentication(
  response: AuthenticationResponseJSON,
) {
  const challenge = getChallengeCookie(AUTH_COOKIE);
  if (!challenge) {
    throw new Error("Authentication session expired. Please try again.");
  }

  const storedPasskey = await findPasskeyByCredentialId(response.id);
  if (!storedPasskey || storedPasskey.operator_account_id !== challenge.accountId) {
    throw new Error("Passkey not recognized for this account.");
  }

  const credential: WebAuthnCredential = {
    id: storedPasskey.credential_id,
    publicKey: isoBase64URL.toBuffer(storedPasskey.public_key),
    counter: storedPasskey.counter,
    transports: storedPasskey.transports as AuthenticatorTransportFuture[],
  };

  const verified = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: challenge.origin,
    expectedRPID: challenge.rpID,
    credential,
  });

  if (!verified.verified) {
    throw new Error("Passkey authentication failed.");
  }

  await updatePasskeyCounter(storedPasskey.id, verified.authenticationInfo.newCounter);
  cookies().delete(AUTH_COOKIE);

  return challenge.accountId;
}

function getRpConfig(request: Request) {
  const requestUrl = new URL(request.url);
  const host = request.headers.get("x-forwarded-host") || requestUrl.host;
  const protocol = request.headers.get("x-forwarded-proto") || requestUrl.protocol.replace(":", "");
  const hostname = host.split(":")[0];

  return {
    origin: `${protocol}://${host}`,
    rpID: hostname,
  };
}

function setChallengeCookie(name: string, state: ChallengeState) {
  cookies().set(name, Buffer.from(JSON.stringify(state)).toString("base64url"), {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: new Date(state.expiresAt),
    priority: "high",
  });
}

function getChallengeCookie(name: string): ChallengeState | null {
  const encoded = cookies().get(name)?.value;
  if (!encoded) {
    return null;
  }

  try {
    const state = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as ChallengeState;
    if (state.expiresAt < Date.now()) {
      cookies().delete(name);
      return null;
    }

    return state;
  } catch {
    cookies().delete(name);
    return null;
  }
}
