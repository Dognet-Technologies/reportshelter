/**
 * Banner shown when a project is locked by another user.
 */
import { Lock } from "lucide-react";
import { format } from "date-fns";
import type { ProjectLock } from "@/api/types";

interface ProjectLockBannerProps {
  lock: ProjectLock;
}

export function ProjectLockBanner({ lock }: ProjectLockBannerProps) {
  const lockedAt = new Date(lock.locked_at);
  const timeStr = format(lockedAt, "HH:mm");

  return (
    <div className="flex items-center gap-2 rounded-lg border border-amber-700 bg-amber-900/30 px-4 py-3 text-sm text-amber-300">
      <Lock className="h-4 w-4 shrink-0" />
      <span>
        This project is currently being edited by{" "}
        <strong className="font-semibold">{lock.locked_by_name}</strong> since{" "}
        <strong className="font-semibold">{timeStr}</strong>. You are in read-only mode.
      </span>
    </div>
  );
}
