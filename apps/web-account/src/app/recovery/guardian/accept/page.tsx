import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AuthShell } from "@/components/AuthShell";
import { GuardianAcceptPanel } from "./GuardianAcceptPanel";
import { env } from "@/lib/env";
import { firstParam } from "@/lib/searchParams";

/**
 * Authn Platform — Guardian invitation landing
 * File: apps/web-account/src/app/recovery/guardian/accept/page.tsx
 *
 * Where a guardian invitation link lands. The engine builds these as
 * `/recovery/guardian/accept?id=<contact>#token=<hex>&share=<hex>`, so without this
 * route every link it issues is a 404 and no guardian can ever be activated.
 *
 * Public, and outside `/account`, because the person opening it is a third party who
 * usually has no account here at all.
 *
 * Only `id` is read on the server. The token and the share ride in the fragment,
 * which a browser never sends to a server — that is what keeps them out of the
 * engine's access log and out of the `Referer` header — so they exist nowhere this
 * component can see them and the panel below reads them from the address bar.
 */

export const metadata: Metadata = {
  title: "Be a recovery guardian",
  description: "Confirm that you will help someone you trust get back into their account.",
};

export default async function GuardianAcceptPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<ReactNode> {
  const params = await searchParams;

  return (
    <AuthShell
      brand={`Authn · v${env.appVersion}`}
      title="Recovery guardian"
      subtitle="Someone you know has asked you to help them get back into their account if they are ever locked out."
      footer="Being a guardian never gives you access to the account you help protect."
    >
      <GuardianAcceptPanel contactId={firstParam(params["id"])} />
    </AuthShell>
  );
}
