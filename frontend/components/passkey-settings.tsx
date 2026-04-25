"use client";

import { startRegistration } from "@simplewebauthn/browser";
import { useState } from "react";

export function PasskeySettings({
  companyName,
  passkeyCount,
}: {
  companyName: string;
  passkeyCount: number;
}) {
  const [isBusy, setIsBusy] = useState(false);
  const [enrolledCount, setEnrolledCount] = useState(passkeyCount);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function setupPasskey() {
    setIsBusy(true);
    setMessage(null);
    setError(null);

    try {
      const optionsResponse = await fetch("/api/auth/passkeys/register/options", {
        method: "POST",
      });
      const optionsPayload = await optionsResponse.json();
      if (!optionsResponse.ok) {
        throw new Error(optionsPayload.error || "Unable to start passkey setup.");
      }

      const registration = await startRegistration({
        optionsJSON: optionsPayload,
      });

      const verifyResponse = await fetch("/api/auth/passkeys/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: registration }),
      });
      const verifyPayload = await verifyResponse.json();
      if (!verifyResponse.ok) {
        throw new Error(verifyPayload.error || "Unable to verify passkey.");
      }

      setEnrolledCount((current) => current + 1);
      setMessage("Passkey enrolled successfully.");
    } catch (passkeyError) {
      setError(
        passkeyError instanceof Error
          ? passkeyError.message
          : "Unable to set up passkey.",
      );
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <div className="panel p-7">
      <p className="micro-label">Authentication</p>
      <h2 className="mt-4 font-display text-2xl font-semibold tracking-[-0.03em] text-text-1">
        {companyName} security settings
      </h2>
      <p className="mt-4 text-sm leading-7 text-text-2">
        Password login is available by default. You can also enroll passkeys
        for phishing-resistant sign-ins and use email OTP as a fallback.
      </p>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <div className="product-card p-4">
          <p className="micro-label">Passkeys enrolled</p>
          <p className="mt-2 text-3xl font-semibold text-text-1">
            {enrolledCount}
          </p>
        </div>
        <div className="product-card p-4">
          <p className="micro-label">Fallback login</p>
          <p className="mt-2 text-sm font-medium text-text-1">Email OTP</p>
        </div>
      </div>

      <button
        onClick={setupPasskey}
        disabled={isBusy}
        className="mt-6 rounded-full border border-signal/25 bg-signal/[0.08] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/45 disabled:cursor-not-allowed disabled:opacity-70"
      >
        {isBusy ? "Setting up..." : "Set up passkey"}
      </button>

      {message ? (
        <div className="mt-4 rounded-2xl border border-signal/30 bg-signal/[0.08] px-4 py-3 text-sm text-signal">
          {message}
        </div>
      ) : null}

      {error ? (
        <div className="mt-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}
    </div>
  );
}
