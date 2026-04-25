import Link from "next/link";
import { redirect } from "next/navigation";
import { SiteChrome } from "@/components/site-chrome";
import { SignInClient } from "@/components/sign-in-client";
import { sanitizeNextPath } from "@/lib/navigation";
import { getOptionalSessionAccount } from "@/lib/server/auth";

export default async function SignInPage({
  searchParams,
}: {
  searchParams?: { next?: string | string[] };
}) {
  const nextPath = sanitizeNextPath(searchParams?.next, "/account");
  const account = await getOptionalSessionAccount();
  if (account) {
    redirect(nextPath);
  }

  return (
    <SiteChrome accent="operator authentication" signedIn={false}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Sign in</span>
          <h1 className="section-title mt-6">
            Access Ghost as a protocol operator
          </h1>
          <p className="section-copy mx-auto mt-6">
            Enter your work email to receive a one-time sign-in code, switch to
            password when needed, or continue with a registered passkey.
          </p>
        </div>

        <div className="mt-14">
          <SignInClient nextPath={nextPath} />
        </div>

        <div className="mt-8 text-center text-sm text-text-2">
          New team?{" "}
          <Link href="/sign-up" className="text-signal transition hover:brightness-110">
            Create an operator account
          </Link>
        </div>
      </main>
    </SiteChrome>
  );
}
