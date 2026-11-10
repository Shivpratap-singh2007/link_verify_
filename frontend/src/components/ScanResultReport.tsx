import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Cpu,
  Globe,
  Info,
  Lock,
  LockOpen,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { CircularRiskGauge } from "@/components/CircularRiskGauge";
import { RiskBadge } from "@/components/RiskBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, formatProviderName, formatTimestamp, getRiskColors } from "@/lib/utils";
import type { ScanReport } from "@/types/api";

function getSeverityBadgeVariant(severity: string): "outline" | "low" | "medium" | "high" | "critical" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "outline";
  }
}

function getIntelStatusBadge(status: string) {
  switch (status) {
    case "malicious":
      return <Badge variant="critical">Malicious</Badge>;
    case "suspicious":
      return <Badge variant="high">Suspicious</Badge>;
    case "clean":
      return <Badge variant="low">No Known Match</Badge>;
    case "not_configured":
      return <Badge variant="outline">Not Configured</Badge>;
    case "rate_limited":
      return <Badge variant="medium">Rate Limited</Badge>;
    default:
      return <Badge variant="outline">Unavailable</Badge>;
  }
}

export function ScanResultReport({ report }: { report: ScanReport }) {
  const colors = getRiskColors(report.risk_level);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button variant="outline" size="sm" asChild>
          <Link to="/scanner">
            <ArrowLeft className="h-4 w-4" />
            New Scan
          </Link>
        </Button>
        <div className="text-xs text-muted flex items-center gap-2">
          <span>Scanned: {formatTimestamp(report.scanned_at)}</span>
          {report.persisted ? (
            <Badge variant="default">Saved to History</Badge>
          ) : (
            <Badge variant="outline">Session Report (Sign in to save)</Badge>
          )}
        </div>
      </div>

      {/* Primary Summary Header Card */}
      <Card className={cn("border-2", colors.border)}>
        <CardContent className="p-6">
          <div className="flex flex-col lg:flex-row items-center lg:items-start gap-8">
            <div className="shrink-0 flex flex-col items-center gap-3">
              <CircularRiskGauge score={report.risk_score} riskLevel={report.risk_level} />
              <RiskBadge level={report.risk_level} />
            </div>

            <div className="flex-1 min-w-0 space-y-4 w-full">
              <div>
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                    Submitted URL
                  </span>
                  {report.is_https ? (
                    <Badge variant="low">
                      <Lock className="h-3 w-3" /> HTTPS
                    </Badge>
                  ) : (
                    <Badge variant="medium">
                      <LockOpen className="h-3 w-3" /> HTTP (Unencrypted)
                    </Badge>
                  )}
                </div>
                <p className="font-mono text-sm sm:text-base break-all bg-surface-elevated border border-border rounded-lg px-3.5 py-2.5">
                  {report.submitted_url}
                </p>
              </div>

              <div className={cn("rounded-lg border p-3.5", colors.bg, colors.border)}>
                <div className="flex items-start gap-2.5">
                  {report.risk_level === "LOW" ? (
                    <ShieldCheck className={cn("h-5 w-5 shrink-0 mt-0.5", colors.text)} />
                  ) : (
                    <ShieldAlert className={cn("h-5 w-5 shrink-0 mt-0.5", colors.text)} />
                  )}
                  <div>
                    <p className={cn("font-semibold text-sm", colors.text)}>{report.verdict}</p>
                    <p className="text-xs text-muted mt-1">{report.safety_disclaimer}</p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="rounded-lg border border-border bg-surface-elevated/60 p-3">
                  <div className="flex items-center gap-1.5 text-xs text-muted">
                    <Globe className="h-3.5 w-3.5 text-secondary" />
                    Destination Host
                  </div>
                  <p className="font-mono text-sm font-medium mt-1 truncate" title={report.normalized_domain}>
                    {report.normalized_domain}
                  </p>
                  <p className="text-[11px] text-muted mt-0.5 truncate">
                    Registered: {report.registered_domain}
                  </p>
                </div>

                <div className="rounded-lg border border-border bg-surface-elevated/60 p-3">
                  <div className="flex items-center gap-1.5 text-xs text-muted">
                    <Cpu className="h-3.5 w-3.5 text-secondary" />
                    ML Model Confidence
                  </div>
                  {report.ml_details.model_loaded && report.model_confidence !== null ? (
                    <>
                      <p className="text-sm font-semibold mt-1 tabular-nums">
                        {(report.model_confidence * 100).toFixed(1)}%{" "}
                        <span className="text-xs font-normal text-muted uppercase">
                          ({report.ml_details.predicted_label})
                        </span>
                      </p>
                      <p className="text-[11px] text-muted mt-0.5">
                        P(phishing): {((report.ml_details.phishing_probability ?? 0) * 100).toFixed(1)}% ·{" "}
                        {report.ml_details.model_name}
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-sm font-medium mt-1 text-muted">Not Trained</p>
                      <p className="text-[11px] text-muted mt-0.5">{report.ml_details.status_message}</p>
                    </>
                  )}
                </div>

                <div className="rounded-lg border border-border bg-surface-elevated/60 p-3">
                  <div className="flex items-center gap-1.5 text-xs text-muted">
                    <Info className="h-3.5 w-3.5 text-secondary" />
                    Threat Intelligence
                  </div>
                  <p className="text-sm font-semibold mt-1 capitalize">
                    {report.threat_intel_status.replaceAll("_", " ")}
                  </p>
                  <p className="text-[11px] text-muted mt-0.5">
                    {report.threat_intelligence.length} provider feeds evaluated
                  </p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detection Indicators & Security Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Detection Indicators ({report.detection_indicators.length})</CardTitle>
            <CardDescription>
              Explainable structural, lexical, and domain signals identified during static inspection.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {report.detection_indicators.length === 0 ? (
              <div className="rounded-lg border border-border bg-surface-elevated/50 p-4 flex items-center gap-3 text-sm text-muted">
                <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <span>No suspicious structural or lexical anomalies were flagged by heuristic rules.</span>
              </div>
            ) : (
              <div className="space-y-3">
                {report.detection_indicators.map((ind) => (
                  <div
                    key={ind.code}
                    className="rounded-lg border border-border bg-surface-elevated/40 p-4 space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                        <span className="font-medium text-sm">{ind.title}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getSeverityBadgeVariant(ind.severity)}>
                          {ind.severity.toUpperCase()}
                        </Badge>
                        <span className="text-xs font-mono text-muted">+{ind.contribution}</span>
                      </div>
                    </div>
                    <p className="text-xs text-muted leading-relaxed">{ind.description}</p>
                    {ind.evidence && (
                      <p className="text-xs font-mono text-secondary bg-surface px-2.5 py-1 rounded border border-border inline-block break-all">
                        Evidence: {ind.evidence}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Security Recommendations</CardTitle>
              <CardDescription>Actionable next steps before interacting with this link.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2.5 text-sm">
                {report.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-muted">
                    <ShieldCheck className="h-4 w-4 text-secondary shrink-0 mt-0.5" />
                    <span className="text-xs leading-relaxed text-foreground/90">{rec}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Evidence Weighting</CardTitle>
              <CardDescription>How the final 0–100 risk score was computed.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {report.evidence_breakdown.map((ev) => (
                <div
                  key={ev.source}
                  className="rounded-lg border border-border bg-surface-elevated/50 p-3 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between font-medium">
                    <span>{ev.source}</span>
                    <span className="font-mono text-secondary">
                      {ev.raw_score !== null ? `${ev.raw_score.toFixed(1)}/100` : "N/A"} · w=
                      {(ev.effective_weight * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-muted">{ev.summary}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Threat Intelligence Provider Status */}
      <Card>
        <CardHeader>
          <CardTitle>Threat Intelligence Feeds</CardTitle>
          <CardDescription>
            Server-side reputation lookups. API credentials are never exposed to the browser.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {report.threat_intelligence.map((ti) => (
              <div
                key={ti.provider}
                className="rounded-lg border border-border bg-surface-elevated/50 p-3.5 space-y-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{formatProviderName(ti.provider)}</span>
                  {getIntelStatusBadge(ti.detection_status)}
                </div>
                <p className="text-xs text-muted leading-relaxed">{ti.message}</p>
                {ti.cached && <span className="text-[11px] font-mono text-secondary">Cached result</span>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Extracted Features Table */}
      <Card>
        <CardHeader>
          <CardTitle>Extracted URL Features ({report.extracted_features.length})</CardTitle>
          <CardDescription>
            Static lexical and structural attributes computed without visiting or executing the URL.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2.5">
            {report.extracted_features.map((feat) => (
              <div
                key={feat.feature_name}
                className="rounded-lg border border-border bg-surface-elevated/50 px-3 py-2 text-xs"
              >
                <div className="font-mono text-[11px] text-muted truncate" title={feat.feature_name}>
                  {feat.feature_name}
                </div>
                <div className="font-mono font-semibold text-sm mt-0.5 text-foreground">
                  {feat.feature_value}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
