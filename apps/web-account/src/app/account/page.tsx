import type { Metadata } from "next";
import type { ReactNode } from "react";
import { IdCardIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { ProfileCards } from "./ProfileCards";

/**
 * Authn Platform — Profile page
 * File: apps/web-account/src/app/account/page.tsx
 *
 * The header renders on the server; the cards are a client component because every
 * value in them comes from `GET /v1/client/user/profile` over an authenticated
 * request, and the credential for that lives in the browser.
 *
 * The fields are the ones the profile DTO can *write* and no others. The phone
 * number is carried in the response but `PATCH /v1/client/user/profile` does not
 * accept it — it is confirmed by code as part of setting up text-message
 * verification — so it is on the security page and not here. An input that cannot
 * be saved is worse than a missing feature, because the reader finds out only after
 * typing.
 */

export const metadata: Metadata = { title: "Profile" };

export default function ProfilePage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Profile"
        description="Your name, your handle, and the address we use to reach you. This is what other people see when you join an organization."
        illustration={IdCardIllustration}
        accent="blue"
      />

      <ProfileCards />
    </>
  );
}
