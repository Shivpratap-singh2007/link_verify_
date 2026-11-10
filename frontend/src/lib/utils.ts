import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { RiskLevel } from "@/types/api";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getRiskColors(level: RiskLevel) {
  switch (level) {
    case "LOW":
      return {
        text: "text-emerald-700 dark:text-emerald-400",
        bg: "bg-emerald-50 dark:bg-emerald-500/10",
        border: "border-emerald-200 dark:border-emerald-500/30",
        stroke: "#16A34A",
      };
    case "MEDIUM":
      return {
        text: "text-amber-700 dark:text-amber-400",
        bg: "bg-amber-50 dark:bg-amber-500/10",
        border: "border-amber-200 dark:border-amber-500/30",
        stroke: "#D97706",
      };
    case "HIGH":
      return {
        text: "text-orange-700 dark:text-orange-400",
        bg: "bg-orange-50 dark:bg-orange-500/10",
        border: "border-orange-200 dark:border-orange-500/30",
        stroke: "#EA580C",
      };
    case "CRITICAL":
      return {
        text: "text-red-700 dark:text-red-400",
        bg: "bg-red-50 dark:bg-red-500/10",
        border: "border-red-200 dark:border-red-500/30",
        stroke: "#DC2626",
      };
  }
}

export function formatProviderName(provider: string): string {
  switch (provider) {
    case "google_safe_browsing":
      return "Google Safe Browsing";
    case "virustotal":
      return "VirusTotal";
    case "phishtank":
      return "PhishTank";
    case "urlhaus":
      return "URLhaus";
    default:
      return provider;
  }
}

export function formatTimestamp(iso: string): string {
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
