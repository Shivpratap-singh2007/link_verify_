import { useEffect, useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

const STAGES = [
  "Validating URL & SSRF boundaries",
  "Extracting lexical & domain features",
  "Running ML phishing classifier",
  "Querying threat intelligence feeds",
  "Aggregating explainable risk report",
];

export function ScanProgress({ active }: { active: boolean }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (!active) {
      setStep(0);
      return;
    }
    setStep(0);
    const interval = setInterval(() => {
      setStep((prev) => (prev < STAGES.length - 1 ? prev + 1 : prev));
    }, 380);
    return () => clearInterval(interval);
  }, [active]);

  if (!active) return null;

  const progressPct = Math.round(((step + 1) / STAGES.length) * 100);

  return (
    <div
      className="rounded-xl border border-blue-200 dark:border-secondary/40 bg-blue-50/40 dark:bg-surface p-5 space-y-4"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-foreground flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-secondary" />
          Analyzing URL statically...
        </span>
        <span className="font-mono text-xs text-secondary font-semibold">{progressPct}%</span>
      </div>

      <div className="h-1.5 w-full rounded-full bg-surface-elevated overflow-hidden">
        <div
          className="h-full bg-secondary transition-all duration-300"
          style={{ width: `${progressPct}%` }}
        />
      </div>

      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
        {STAGES.map((label, idx) => {
          const done = idx < step;
          const current = idx === step;
          return (
            <li
              key={label}
              className={cn(
                "flex items-center gap-2",
                done
                  ? "text-emerald-700 dark:text-emerald-400"
                  : current
                    ? "text-foreground font-medium"
                    : "text-muted",
              )}
            >
              {done ? (
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <span
                  className={cn(
                    "h-2 w-2 rounded-full shrink-0",
                    current ? "bg-secondary animate-pulse" : "bg-border",
                  )}
                />
              )}
              <span>{label}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
