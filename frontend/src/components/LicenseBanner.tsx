/**
 * Persistent banner shown when the license is expired, invalid, or the trial
 * is ending soon.
 *
 * Rules:
 *  - Trial ending soon (< 7 days): amber, dismissible.
 *  - Expired / invalid: red, NOT dismissible — user must act.
 */
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useLicenseStatus } from "@/api/hooks";

const SALES_EMAIL = "sales@dognet-technologies.online";

export function LicenseBanner() {
  const [dismissed, setDismissed] = useState(false);
  const { data: license } = useLicenseStatus();

  if (!license) return null;

  const isTrialEndingSoon =
    license.status === "trial_active" &&
    license.days_remaining !== null &&
    license.days_remaining < 7;

  const isExpired =
    license.status === "trial_expired" || license.status === "pro_expired";

  const isInvalid = license.status === "invalid";
  const isBlocked = isExpired || isInvalid;

  // Dismissible only for "trial ending soon" warning — never for expired/invalid.
  if (!isTrialEndingSoon && !isBlocked) return null;
  if (isTrialEndingSoon && dismissed) return null;

  // ── Expired / invalid ─────────────────────────────────────────────────────
  if (isBlocked) {
    const label =
      isInvalid
        ? "Your license is invalid."
        : license.status === "trial_expired"
        ? "Your 30-day trial has expired."
        : "Your PRO license has expired.";

    return (
      <div className="flex flex-col gap-2 border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-200">
        <div className="flex items-center gap-2 font-semibold">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          <span>{label}</span>
        </div>
        <p>
          Creating projects, importing scans, and exporting reports is disabled.
          Read-only access to existing data is still available.
        </p>
        <p>
          To purchase a license or for custom requirements, contact{" "}
          <a
            href={`mailto:${SALES_EMAIL}`}
            className="underline font-medium hover:opacity-80"
          >
            {SALES_EMAIL}
          </a>
          {" "}or{" "}
          <Link to="/settings" className="underline font-medium hover:opacity-80">
            activate an existing license
          </Link>
          .
        </p>
      </div>
    );
  }

  // ── Trial ending soon ─────────────────────────────────────────────────────
  return (
    <div className="flex items-center justify-between gap-3 border border-amber-700 bg-amber-950 px-4 py-3 text-sm text-amber-200">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>
          Your trial expires in{" "}
          <strong>
            {license.days_remaining} day{license.days_remaining === 1 ? "" : "s"}
          </strong>
          .{" "}
          <Link to="/settings" className="underline font-medium hover:opacity-80">
            Activate a PRO license
          </Link>{" "}
          or contact{" "}
          <a
            href={`mailto:${SALES_EMAIL}`}
            className="underline hover:opacity-80"
          >
            {SALES_EMAIL}
          </a>
          .
        </span>
      </div>
      <button
        onClick={() => setDismissed(true)}
        className="shrink-0 text-amber-400 hover:opacity-80 text-xs"
        aria-label="Dismiss banner"
      >
        Dismiss
      </button>
    </div>
  );
}
