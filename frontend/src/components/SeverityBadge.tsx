/**
 * Colored badge component for vulnerability risk levels.
 */
import type { RiskLevel } from "@/api/types";

interface SeverityBadgeProps {
  level: RiskLevel;
  className?: string;
}

const SEVERITY_CLASSES: Record<RiskLevel, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  info: "badge-info",
};

export function SeverityBadge({ level, className = "" }: SeverityBadgeProps) {
  const display = level.charAt(0).toUpperCase() + level.slice(1);
  return (
    <span className={`${SEVERITY_CLASSES[level] ?? "badge-info"} ${className}`}>{display}</span>
  );
}
