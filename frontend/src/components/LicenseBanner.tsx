/**
 * Persistent banner shown when license is expired or trial ending soon.
 */
import { AlertTriangle, X } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useLicenseStatus } from "@/api/hooks";

export function LicenseBanner() {
  const [dismissed, setDismissed] = useState(false);
  const { data: license } = useLicenseStatus();

  if (!license || dismissed) return null;

  const isTrialEndingSoon =
    license.status === "trial_active" &&
    license.days_remaining !== null &&
    license.days_remaining < 7;
  const isExpired =
    license.status === "trial_expired" || license.status === "pro_expired";
  const isInvalid = license.status === "invalid";

  if (!isTrialEndingSoon && !isExpired && !isInvalid) return null;

  let message = "";
  let colorClass = "";

  if (isInvalid) {
    message = "Your license is invalid. Please contact support.";
    colorClass = "bg-red-900 border-red-700 text-red-200";
  } else if (isExpired) {
    const label =
      license.status === "trial_expired" ? "trial has expired" : "license has expired";
    message = `Your ${label}. You are in read-only mode. Upgrade to PRO to regain full access.`;
    colorClass = "bg-red-900 border-red-700 text-red-200";
  } else if (isTrialEndingSoon) {
    message = `Your trial expires in ${license.days_remaining} day${license.days_remaining === 1 ? "" : "s"}. Upgrade to PRO to keep full access.`;
    colorClass = "bg-amber-900 border-amber-700 text-amber-200";
  }

  return (
    <div
      className={`flex items-center justify-between gap-3 border px-4 py-3 text-sm ${colorClass}`}
    >
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>{message}</span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <Link to="/settings" className="underline font-medium hover:opacity-80">
          Activate License
        </Link>
        {!isInvalid && (
          <button
            onClick={() => setDismissed(true)}
            className="hover:opacity-80"
            aria-label="Dismiss banner"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
