/**
 * Colored badge component for vulnerability risk levels.
 */
import type { RiskLevel } from "@/api/types";

interface SeverityBadgeProps {
  level: RiskLevel;
  className?: string;
}

const SEVERITY_CLASSES: Record<RiskLevel, string> = {
  Critical: "badge-critical",
  High: "badge-high",
  Medium: "badge-medium",
  Low: "badge-low",
  Info: "badge-info",
};

export function SeverityBadge({ level, className = "" }: SeverityBadgeProps) {
  return (
    <span className={`${SEVERITY_CLASSES[level]} ${className}`}>{level}</span>
  );
}
