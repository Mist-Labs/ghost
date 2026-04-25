"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { SignOutButton } from "@/components/sign-out-button";
import { navItems } from "@/lib/site";
import { cn } from "@/lib/utils";

export function SiteChrome({
  children,
  accent = "monitoring live",
  signedIn = false,
}: {
  children: React.ReactNode;
  accent?: string;
  signedIn?: boolean;
}) {
  const pathname = usePathname();

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="absolute inset-0 -z-10">
        <div className="absolute inset-x-0 top-0 h-px bg-white/10" />
        <div className="absolute left-1/2 top-[-18rem] h-[40rem] w-[40rem] -translate-x-1/2 rounded-full bg-[radial-gradient(circle,rgba(0,230,118,0.09),transparent_67%)]" />
        <div className="absolute left-[-10rem] top-[28rem] h-[22rem] w-[22rem] rounded-full bg-[radial-gradient(circle,rgba(79,195,247,0.06),transparent_72%)]" />
        <div className="absolute right-[-10rem] top-[32rem] h-[22rem] w-[22rem] rounded-full bg-[radial-gradient(circle,rgba(255,255,255,0.03),transparent_72%)]" />
      </div>

      <header className="sticky top-0 z-40 border-b border-white/5 bg-[#050607]/80 backdrop-blur-xl">
        <div className="shell flex h-16 items-center justify-between gap-6">
          <Link href="/" className="flex items-center gap-3">
            <span className="font-display text-xl font-bold text-signal">◈</span>
            <span className="font-display text-sm font-bold tracking-[0.28em] text-text-1">
              GHOST
            </span>
            <span className="rounded-sm border border-white/10 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-text-3">
              v2.1
            </span>
          </Link>

          <nav className="hidden items-center gap-6 lg:flex">
            {navItems.map((item) => {
              const active =
                item.href === "/"
                  ? pathname === item.href
                  : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  style={active ? { color: "var(--signal)" } : undefined}
                  className={cn(
                    "text-sm tracking-[0.02em] text-text-2 transition-colors hover:text-text-1",
                    active && "text-signal hover:text-signal",
                  )}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="flex items-center gap-3">
            {signedIn ? (
              <>
                <Link
                  href="/account"
                  className="rounded-full border border-signal/20 bg-signal/[0.08] px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-signal transition hover:border-signal/40 hover:bg-signal/[0.12]"
                >
                  Account
                </Link>
                <SignOutButton />
              </>
            ) : (
              <>
                <Link
                  href="/sign-in"
                  className="hidden rounded-full border border-white/10 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-text-2 transition hover:border-white/20 hover:text-text-1 md:inline-flex"
                >
                  Sign in
                </Link>
                <Link
                  href="/sign-up"
                  className="rounded-full border border-white/10 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-text-2 transition hover:border-white/20 hover:text-text-1"
                >
                  Sign up
                </Link>
              </>
            )}

            <div className="hidden items-center gap-2 pl-2 md:inline-flex">
              <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-text-3">
                Status
              </span>
              <span
                aria-label="Ghost status live"
                className="inline-block h-2 w-2 rounded-full bg-signal shadow-[0_0_10px_rgba(0,230,118,0.5)] animate-pulse"
              />
            </div>
          </div>
        </div>
      </header>

      {children}

      <footer className="border-t border-white/5 py-8">
        <div className="shell flex flex-col gap-6 text-sm text-text-2 md:flex-row md:items-center md:justify-between">
          <p className="max-w-2xl leading-7">
            Ghost gives protocol teams one operating surface for preventive
            monitoring, incident confirmation, evidence handling, and
            operator-approved response.
          </p>
          <div className="flex flex-wrap gap-4 font-mono text-[11px] uppercase tracking-[0.16em] text-text-3">
            <Link href="/docs">Docs</Link>
            <Link href="/protocols">Protocols</Link>
            <Link href="/pricing">Pricing</Link>
            {signedIn ? <Link href="/account">Account</Link> : null}
            <a
              href="https://github.com/okoliEvans/ghost-ai"
              target="_blank"
              rel="noreferrer"
              aria-label="Ghost GitHub repository"
              className="inline-flex items-center transition hover:text-text-1"
            >
              <svg
                aria-hidden="true"
                viewBox="0 0 16 16"
                className="h-4 w-4 fill-current"
              >
                <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.7 7.7 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
              </svg>
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
