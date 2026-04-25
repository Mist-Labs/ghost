import { OperatorProtocolWorkspace } from "@/components/operator-protocol-workspace";
import { PasskeySettings } from "@/components/passkey-settings";
import { SignOutButton } from "@/components/sign-out-button";
import { SiteChrome } from "@/components/site-chrome";
import {
  listPasskeysForAccount,
  requireSessionAccount,
} from "@/lib/server/auth";
import { loadActiveProtocols } from "@/lib/protocols";
import { listOperatorProtocols } from "@/lib/server/operator-protocols";

export default async function AccountPage() {
  const account = await requireSessionAccount();
  const protocols = await listOperatorProtocols(account.id);
  const fallbackProtocols = await loadActiveProtocols();
  const passkeys = await listPasskeysForAccount(account.id);
  const defaultChainId = Number.parseInt(process.env.CHAIN_ID ?? "84532", 10);

  return (
    <SiteChrome accent="operator account" signedIn>
      <main className="shell py-16 md:py-20">
        <div className="page-hero">
          <span className="eyebrow eyebrow-centered">Account</span>
          <h1 className="subsection-title mt-6">
            Protocol operations and live analysis.
          </h1>
          <p className="section-copy mx-auto mt-6">
            Manage watchlists, contacts, and real-time scans from one account.
          </p>
        </div>

        <div className="mt-10 flex items-center justify-between gap-4 rounded-3xl border border-white/10 bg-[#0a0f12] px-6 py-5">
          <div>
            <p className="micro-label">Signed in as</p>
            <p className="mt-2 font-display text-2xl font-semibold tracking-[-0.03em] text-text-1">
              {account.company_name}
            </p>
            <p className="mt-1 text-sm text-text-2">
              {account.contact_name} · {account.email}
            </p>
          </div>
          <SignOutButton />
        </div>

        <div className="mt-14 space-y-6">
          <PasskeySettings
            companyName={account.company_name}
            passkeyCount={passkeys.length}
          />
          <OperatorProtocolWorkspace
            initialProtocols={protocols}
            fallbackProtocols={fallbackProtocols}
            defaultChainId={Number.isFinite(defaultChainId) ? defaultChainId : 84532}
          />
        </div>
      </main>
    </SiteChrome>
  );
}
