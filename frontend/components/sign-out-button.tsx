"use client";

import { useState } from "react";

export function SignOutButton() {
  const [isBusy, setIsBusy] = useState(false);

  async function signOut() {
    setIsBusy(true);

    try {
      const response = await fetch("/api/auth/sign-out", { method: "POST" });
      if (!response.ok) {
        throw new Error("Unable to sign out.");
      }

      window.location.replace("/");
    } catch {
      setIsBusy(false);
    }
  }

  return (
    <button
      onClick={signOut}
      disabled={isBusy}
      className="rounded-full border border-white/10 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-text-2 transition hover:border-white/20 hover:text-text-1 disabled:cursor-not-allowed disabled:opacity-70"
    >
      {isBusy ? "Signing out..." : "Sign out"}
    </button>
  );
}
