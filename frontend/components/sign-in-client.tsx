"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { useEffect, useMemo, useState } from "react";
import { sanitizeNextPath } from "@/lib/navigation";

type Notice = {
  tone: "error" | "success";
  message: string;
};

type BusyState =
  | "idle"
  | "otp-send"
  | "otp-verify"
  | "password"
  | "passkey";

export function SignInClient({ nextPath = "/account" }: { nextPath?: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordMode, setShowPasswordMode] = useState(false);
  const [otpCode, setOtpCode] = useState("");
  const [otpAttemptedEmail, setOtpAttemptedEmail] = useState("");
  const [otpRequestedEmail, setOtpRequestedEmail] = useState("");
  const [otpModalOpen, setOtpModalOpen] = useState(false);
  const [passkeyAvailable, setPasskeyAvailable] = useState(false);
  const [signInMethodsCheckedEmail, setSignInMethodsCheckedEmail] = useState("");
  const [lastAttemptedOtpCode, setLastAttemptedOtpCode] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busyState, setBusyState] = useState<BusyState>("idle");

  const normalizedEmail = useMemo(() => email.trim().toLowerCase(), [email]);
  const validEmail = normalizedEmail.includes("@");
  const isBusy = busyState !== "idle";
  const passkeyDisabled =
    !validEmail || busyState === "passkey" || busyState === "otp-verify";

  function completeAuthNavigation() {
    window.location.replace(sanitizeNextPath(nextPath));
  }

  useEffect(() => {
    setOtpCode("");
    setLastAttemptedOtpCode("");
    setOtpModalOpen(false);
    setOtpAttemptedEmail("");
    setOtpRequestedEmail("");
    setPasskeyAvailable(false);
    setSignInMethodsCheckedEmail("");
  }, [normalizedEmail]);

  useEffect(() => {
    if (notice?.tone !== "success") {
      return;
    }

    const timer = window.setTimeout(() => {
      setNotice((current) => (current?.tone === "success" ? null : current));
    }, 5000);

    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (
      !validEmail ||
      signInMethodsCheckedEmail === normalizedEmail ||
      busyState !== "idle"
    ) {
      return;
    }

    const timer = window.setTimeout(() => {
      void resolveSignInMethods(normalizedEmail);
    }, 650);

    return () => window.clearTimeout(timer);
  }, [busyState, normalizedEmail, signInMethodsCheckedEmail, validEmail]);

  useEffect(() => {
    if (otpCode.length < 6) {
      setLastAttemptedOtpCode("");
      return;
    }

    if (!otpModalOpen || busyState === "otp-verify" || otpCode === lastAttemptedOtpCode) {
      return;
    }

    setLastAttemptedOtpCode(otpCode);
    void verifyOtp(normalizedEmail, otpCode);
  }, [busyState, lastAttemptedOtpCode, normalizedEmail, otpCode, otpModalOpen]);

  async function requestOtp(targetEmail = normalizedEmail) {
    if (!targetEmail || !targetEmail.includes("@")) {
      return;
    }

    setOtpAttemptedEmail(targetEmail);
    setBusyState("otp-send");
    setNotice(null);

    try {
      const response = await fetch("/api/auth/sign-in/otp/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: targetEmail }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(payload?.error || "Unable to send OTP.");
      }

      setOtpRequestedEmail(targetEmail);
      setOtpModalOpen(true);
      setNotice({
        tone: "success",
        message:
          "If this email is registered for email sign-in, a 6-digit code has been sent.",
      });
    } catch (error) {
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "Unable to send OTP.",
      });
    } finally {
      setBusyState("idle");
    }
  }

  async function resolveSignInMethods(targetEmail: string) {
    try {
      const response = await fetch("/api/auth/sign-in/methods", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: targetEmail }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(payload?.error || "Unable to inspect sign-in methods.");
      }

      setSignInMethodsCheckedEmail(targetEmail);
      setPasskeyAvailable(Boolean(payload?.hasPasskey));

      if (!payload?.hasPasskey) {
        await requestOtp(targetEmail);
      }
    } catch (error) {
      setNotice({
        tone: "error",
        message:
          error instanceof Error
            ? error.message
            : "Unable to inspect sign-in methods.",
      });
    }
  }

  async function verifyOtp(targetEmail: string, code: string) {
    if (!targetEmail || code.length !== 6) {
      return;
    }

    setBusyState("otp-verify");
    setNotice(null);

    try {
      const response = await fetch("/api/auth/sign-in/otp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: targetEmail, code }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(payload?.error || "Invalid OTP.");
      }

      completeAuthNavigation();
    } catch (error) {
      setBusyState("idle");
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "Invalid OTP.",
      });
    }
  }

  async function handlePasswordSignIn() {
    setBusyState("password");
    setNotice(null);

    try {
      const response = await fetch("/api/auth/sign-in/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: normalizedEmail, password }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(payload?.error || "Unable to sign in.");
      }

      completeAuthNavigation();
    } catch (error) {
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "Unable to sign in.",
      });
      setBusyState("idle");
    }
  }

  async function signInWithPasskey() {
    setBusyState("passkey");
    setNotice(null);

    try {
      const optionsResponse = await fetch(
        "/api/auth/passkeys/authenticate/options",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: normalizedEmail }),
        },
      );
      const optionsPayload = await optionsResponse.json().catch(() => null);
      if (!optionsResponse.ok) {
        throw new Error(optionsPayload?.error || "Unable to start passkey sign-in.");
      }

      const assertion = await startAuthentication({ optionsJSON: optionsPayload });
      const verifyResponse = await fetch(
        "/api/auth/passkeys/authenticate/verify",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ response: assertion }),
        },
      );
      const verifyPayload = await verifyResponse.json().catch(() => null);
      if (!verifyResponse.ok) {
        throw new Error(verifyPayload?.error || "Unable to verify passkey.");
      }

      completeAuthNavigation();
    } catch (error) {
      setNotice({
        tone: "error",
        message:
          error instanceof Error
            ? error.message
            : "Unable to sign in with passkey.",
      });
      setBusyState("idle");
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <div className="panel p-7 md:p-8">
        <p className="micro-label">Sign in</p>
        <h2 className="mt-4 font-display text-3xl font-semibold tracking-[-0.04em] text-text-1">
          Sign in
        </h2>

        <div className="mt-8 space-y-6">
          <div>
            <label className="micro-label">Email</label>
            <input
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              type="email"
              autoComplete="email"
              className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
              placeholder="security@protocol.xyz"
            />
            <p className="mt-3 text-sm leading-6 text-text-2">
              Enter your registered operator email to get OTP
            </p>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4">
            <button
              type="button"
              onClick={() => setShowPasswordMode((current) => !current)}
              className="inline-flex items-center justify-center rounded-full border border-signal/30 bg-signal/[0.1] px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-signal transition hover:border-signal/55 hover:bg-signal/[0.2] hover:text-signal disabled:cursor-not-allowed disabled:opacity-70"
            >
              {showPasswordMode ? "Hide password sign-in" : "Sign in with password"}
            </button>

            {showPasswordMode ? (
              <div className="mt-4 space-y-4">
                <div className="relative">
                  <input
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    className="w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 pr-20 text-sm text-text-1 outline-none transition focus:border-signal/40"
                    placeholder="Password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((current) => !current)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full border border-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-text-3 transition hover:border-white/20 hover:text-text-1"
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
                <button
                  type="button"
                  onClick={handlePasswordSignIn}
                  disabled={!validEmail || !password || isBusy}
                  className="inline-flex items-center justify-center rounded-full bg-signal px-5 py-3 font-display text-sm font-semibold uppercase tracking-[0.12em] text-black shadow-signal transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {busyState === "password" ? "Signing in..." : "Continue"}
                </button>
              </div>
            ) : null}
          </div>

          <div className="border-t border-white/10 pt-6">
            <p className="font-display text-lg font-semibold tracking-[-0.02em] text-text-1">
              Sign in with passkey
            </p>
            <button
              type="button"
              onClick={signInWithPasskey}
              disabled={passkeyDisabled}
              className="mt-5 inline-flex items-center rounded-full border border-signal/35 bg-signal/[0.1] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/60 hover:bg-signal/[0.18] hover:text-signal disabled:cursor-not-allowed disabled:opacity-70"
            >
              {busyState === "passkey" ? "Continuing..." : "Continue with passkey"}
            </button>
            {passkeyAvailable && !otpModalOpen ? (
              <button
                type="button"
                onClick={() => void requestOtp(normalizedEmail)}
                disabled={isBusy}
                className="mt-4 inline-flex items-center rounded-full border border-white/10 px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-text-2 transition hover:border-white/20 hover:text-text-1 disabled:cursor-not-allowed disabled:opacity-70"
              >
                Use email OTP instead
              </button>
            ) : null}
          </div>

          {notice ? (
            <div
              className={`rounded-2xl border px-4 py-3 text-sm ${
                notice.tone === "error"
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-200"
                  : "border-signal/30 bg-signal/[0.08] text-signal"
              }`}
            >
              {notice.message}
            </div>
          ) : null}
        </div>
      </div>

      {otpModalOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 px-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-3xl border border-white/10 bg-[#0a0f12] p-6 shadow-[0_24px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="micro-label">OTP verification</p>
                <h3 className="mt-3 font-display text-2xl font-semibold tracking-[-0.03em] text-text-1">
                  otp sent, enter to verify.
                </h3>
              </div>
              <button
                type="button"
                onClick={() => {
                  setOtpModalOpen(false);
                  setOtpCode("");
                  setLastAttemptedOtpCode("");
                }}
                className="rounded-full border border-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-text-3 transition hover:border-white/20 hover:text-text-1"
              >
                Close
              </button>
            </div>

            <p className="mt-4 text-sm leading-6 text-text-2">{normalizedEmail}</p>

            <div className="mt-6">
              <div className="flex items-center justify-between gap-3">
                <label className="micro-label">Enter 6-digit code</label>
                <button
                  type="button"
                  onClick={() => void requestOtp(normalizedEmail)}
                  disabled={!validEmail || isBusy}
                  className="font-mono text-[10px] uppercase tracking-[0.16em] text-text-3 transition hover:text-text-1 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {busyState === "otp-send" ? "Sending..." : "Resend code"}
                </button>
              </div>
              <input
                value={otpCode}
                onChange={(event) =>
                  setOtpCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                }
                inputMode="numeric"
                autoComplete="one-time-code"
                className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-center text-sm tracking-[0.45em] text-text-1 outline-none transition focus:border-signal/40"
                placeholder="000000"
              />
            </div>

            <div className="mt-5 border-t border-white/10 pt-5">
              <p className="font-display text-base font-semibold tracking-[-0.02em] text-text-1">
                Or continue with passkey
              </p>
              <button
                type="button"
                onClick={signInWithPasskey}
                disabled={passkeyDisabled}
                className="mt-4 inline-flex items-center rounded-full border border-signal/35 bg-signal/[0.1] px-5 py-3 font-mono text-xs uppercase tracking-[0.16em] text-signal transition hover:border-signal/60 hover:bg-signal/[0.18] hover:text-signal disabled:cursor-not-allowed disabled:opacity-70"
              >
                {busyState === "passkey" ? "Continuing..." : "Continue with passkey"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
