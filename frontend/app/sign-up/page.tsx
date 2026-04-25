import Link from "next/link";
import { redirect } from "next/navigation";
import { SiteChrome } from "@/components/site-chrome";
import { SignUpClient } from "@/components/sign-up-client";
import { getOptionalSessionAccount } from "@/lib/server/auth";

export default async function SignUpPage() {
  const account = await getOptionalSessionAccount();
  if (account) {
    redirect("/account");
  }

  return (
    <SiteChrome accent="organization onboarding" signedIn={false}>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Sign up</span>
          <h1 className="section-title mt-6">
            Create a Ghost account for your protocol team
          </h1>
          <p className="section-copy mx-auto mt-6">
            Ghost is built for DeFi teams, not individual end users. Create an
            organization account, then enroll passkeys and operator workflows
            from your account.
          </p>
        </div>

        <div className="mx-auto mt-14 max-w-4xl">
          <SignUpClient />
        </div>

        <div className="mt-8 text-center text-sm text-text-2">
          Already onboarded?{" "}
          <Link href="/sign-in" className="text-signal transition hover:brightness-110">
            Sign in
          </Link>
        </div>
      </main>
    </SiteChrome>
  );
}
