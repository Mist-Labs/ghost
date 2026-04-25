"use client";

import { useState } from "react";

export function SignUpClient() {
  const [companyName, setCompanyName] = useState("");
  const [contactName, setContactName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit() {
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch("/api/auth/sign-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          companyName,
          contactName,
          email,
          password,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || "Unable to create account.");
      }

      window.location.replace("/account");
    } catch (signUpError) {
      setError(
        signUpError instanceof Error
          ? signUpError.message
          : "Unable to create account.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="panel p-7">
      <p className="micro-label">Organization sign up</p>
      <h2 className="mt-4 font-display text-3xl font-semibold tracking-[-0.04em] text-text-1">
        Create a Ghost operator account
      </h2>
      <p className="mt-4 text-sm leading-7 text-text-2">
        Ghost is built for protocol teams. Use your organization name and a
        work email so the account can receive disclosures, OTP codes, and
        operator alerts.
      </p>

      <div className="mt-8 grid gap-4 md:grid-cols-2">
        <div className="md:col-span-2">
          <label className="micro-label">Company name</label>
          <input
            value={companyName}
            onChange={(event) => setCompanyName(event.target.value)}
            className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
            placeholder="Protocol Labs, ExampleDAO, ..."
          />
        </div>

        <div>
          <label className="micro-label">Contact name</label>
          <input
            value={contactName}
            onChange={(event) => setContactName(event.target.value)}
            className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
            placeholder="Security lead"
          />
        </div>

        <div>
          <label className="micro-label">Work email</label>
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            type="email"
            className="mt-2 w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-1 outline-none transition focus:border-signal/40"
            placeholder="security@protocol.xyz"
          />
        </div>

        <div>
          <label className="micro-label">Password</label>
          <div className="relative mt-2">
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type={showPassword ? "text" : "password"}
              className="w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 pr-20 text-sm text-text-1 outline-none transition focus:border-signal/40"
              placeholder="Create a password"
            />
            <button
              type="button"
              onClick={() => setShowPassword((current) => !current)}
              className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full border border-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-text-3 transition hover:border-white/20 hover:text-text-1"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
        </div>

        <div>
          <label className="micro-label">Confirm password</label>
          <div className="relative mt-2">
            <input
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              type={showConfirmPassword ? "text" : "password"}
              className="w-full rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 pr-20 text-sm text-text-1 outline-none transition focus:border-signal/40"
              placeholder="Repeat password"
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword((current) => !current)}
              className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full border border-white/10 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-text-3 transition hover:border-white/20 hover:text-text-1"
            >
              {showConfirmPassword ? "Hide" : "Show"}
            </button>
          </div>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-white/10 bg-[#0b1013] px-4 py-3 text-sm text-text-2">
        Password rule: at least 7 characters and at least one special
        character.
      </div>

      {error ? (
        <div className="mt-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      <button
        onClick={handleSubmit}
        disabled={isSubmitting}
        className="mt-6 inline-flex items-center justify-center rounded-full bg-signal px-6 py-3 font-display text-sm font-semibold uppercase tracking-[0.12em] text-black shadow-signal transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
      >
        {isSubmitting ? "Creating account..." : "Create account"}
      </button>
    </div>
  );
}
