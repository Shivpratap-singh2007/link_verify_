import { getRiskColors } from "@/lib/utils";
import type { RiskLevel } from "@/types/api";

interface CircularRiskGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  size?: number;
}

export function CircularRiskGauge({ score, riskLevel, size = 168 }: CircularRiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, score));
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (clamped / 100) * circumference;
  const colors = getRiskColors(riskLevel);

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Risk score ${clamped} out of 100, classification ${riskLevel}`}
    >
      <svg width={size} height={size} className="-rotate-90 transform">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-border"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={colors.stroke}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-4xl font-bold tracking-tight tabular-nums">{clamped}</span>
        <span className="text-[11px] uppercase tracking-wider text-muted mt-0.5">Risk Score</span>
        <span className={`text-xs font-semibold mt-1 ${colors.text}`}>{riskLevel}</span>
      </div>
    </div>
  );
}

