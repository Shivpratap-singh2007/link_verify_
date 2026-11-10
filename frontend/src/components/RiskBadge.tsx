import { Badge } from "@/components/ui/badge";
import type { RiskLevel } from "@/types/api";

export function RiskBadge({ level }: { level: RiskLevel }) {
  const variantMap: Record<RiskLevel, "low" | "medium" | "high" | "critical"> = {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
  };
  return <Badge variant={variantMap[level]}>{level}</Badge>;
}

