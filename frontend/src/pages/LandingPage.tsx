import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  CheckCircle2,
  CornerDownLeft,
  Cpu,
  Network,
  Plus,
  ScanSearch,
  Shield,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useToast } from "@/context/ToastContext";
import { api } from "@/services/api";
import { urlInputSchema, type UrlInputFormValues } from "@/utils/urlValidation";

export function LandingPage() {
  const navigate = useNavigate();
  const { notify } = useToast();
  const [submitting, setSubmitting] = useState(false);

  const modelStatusQuery = useQuery({
    queryKey: ["model-status"],
    queryFn: api.getModelStatus,
    staleTime: 60_000,
  });

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<UrlInputFormValues>({
    resolver: zodResolver(urlInputSchema),
    defaultValues: { url: "" },
  });

  const onSubmit = async (values: UrlInputFormValues) => {
    setSubmitting(true);
    try {
      const report = await api.scanUrl(values.url);
      if (report.persisted && report.id) {
        navigate(`/scans/${report.id}`, { state: { report } });
      } else {
        navigate("/scan-result", { state: { report } });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to analyze URL.";
      notify({ title: "Scan failed", description: msg, variant: "error" });
    } finally {
      setSubmitting(false);
    }
  };

  const modelData = modelStatusQuery.data;
  const metrics = modelData?.metrics;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-10 sm:py-14 space-y-12">
      {/* Hero Split Layout matching reference UI */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <div className="lg:col-span-7 space-y-6 pt-2">
          <div className="space-y-3">
            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-foreground leading-[1.12]">
              Don&apos;t Trust Every Link. Verify Before You Click.
            </h1>
            <p className="text-base sm:text-lg text-muted max-w-xl">
              Analyze suspicious URLs using intelligent threat detection and security intelligence.
            </p>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-2.5 max-w-2xl" noValidate>
            <div className="relative flex flex-col sm:flex-row gap-2.5">
              <div className="relative flex-1">
                <Input
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://example.com/verify-account"
                  aria-label="URL to analyze"
                  className="h-11 pr-20 font-mono text-sm bg-surface"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      void handleSubmit(onSubmit)();
                    }
                  }}
                  {...register("url")}
                />
                <span className="hidden sm:inline-flex items-center gap-1 rounded border border-border bg-surface-elevated px-1.5 py-0.5 text-[10px] font-medium text-muted absolute right-2.5 top-2.5 pointer-events-none">
                  <CornerDownLeft className="h-2.5 w-2.5" />
                  Enter
                </span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Button type="submit" size="lg" disabled={submitting} className="h-11 px-5">
                  <Plus className="h-4 w-4" />
                  {submitting ? "Scanning..." : "Scan Now"}
                </Button>
                <Button variant="outline" size="lg" asChild className="h-11 px-4">
                  <Link to="/scanner">Full Scanner</Link>
                </Button>
              </div>
            </div>
            {errors.url && (
              <p className="text-xs text-red-600 dark:text-red-400" role="alert">
                {errors.url.message}
              </p>
            )}
            <p className="text-xs text-muted">
              Paste a link and press <kbd className="font-mono px-1 py-0.5 rounded bg-surface-elevated border border-border text-[11px]">Enter</kbd> or click Scan Now. Submitted links are analyzed statically and never opened.
            </p>
          </form>
        </div>

        {/* Right Engine Overview Card (Live Telemetry Only) */}
        <Card className="lg:col-span-5">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                Engine Overview
              </span>
              {modelData && (
                <Badge variant={modelData.model_loaded ? "low" : "medium"}>
                  {modelData.model_loaded ? "ML Active" : "Not Trained"}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="divide-y divide-border text-sm">
              <div className="py-2.5 flex items-center justify-between">
                <span className="text-muted">Static URL Features</span>
                <span className="font-semibold tabular-nums text-foreground">
                  {modelData ? modelData.feature_names.length : 25}
                </span>
              </div>
              <div className="py-2.5 flex items-center justify-between">
                <span className="text-muted">Test Accuracy ({modelData?.model_name || "ML"})</span>
                <span className="font-semibold tabular-nums text-foreground">
                  {metrics?.accuracy !== undefined ? `${(metrics.accuracy * 100).toFixed(2)}%` : "Pending"}
                </span>
              </div>
              <div className="py-2.5 flex items-center justify-between">
                <span className="text-muted">ROC-AUC / F1-Score</span>
                <span className="font-semibold tabular-nums text-accent-green">
                  {metrics?.roc_auc !== undefined && metrics?.f1_score !== undefined
                    ? `${metrics.roc_auc.toFixed(3)} / ${metrics.f1_score.toFixed(3)}`
                    : "Pending"}
                </span>
              </div>
              <div className="py-2.5 flex items-center justify-between">
                <span className="text-muted">Threat Intel Adapters</span>
                <span className="font-semibold tabular-nums text-secondary">4 Feeds</span>
              </div>
            </div>
            <Button variant="outline" className="w-full" asChild>
              <Link to="/dashboard">View Analytics Dashboard</Link>
            </Button>
          </CardContent>
        </Card>
      </section>

      {/* 3-Card Feature Row matching Screenshot 6 */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <Card>
          <CardHeader>
            <CheckCircle2 className="h-5 w-5 text-secondary mb-2" />
            <CardTitle>Explainable Risk Scoring</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5 text-sm text-muted list-disc pl-4">
              <li>Separate 0–100 risk score and ML model confidence.</li>
              <li>Inspect every heuristic, lexical, and TLD signal triggered.</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <Shield className="h-5 w-5 text-secondary mb-2" />
            <CardTitle>Zero-Execution Safety</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5 text-sm text-muted list-disc pl-4">
              <li>Submitted URLs are never visited or executed by the server.</li>
              <li>Strict SSRF, loopback, and cloud metadata blocks enforced.</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <Network className="h-5 w-5 text-secondary mb-2" />
            <CardTitle>ML &amp; Threat Intelligence</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5 text-sm text-muted list-disc pl-4">
              <li>Trained Random Forest classifier on 11,427 benchmark URLs.</li>
              <li>Integrates Google Safe Browsing, VirusTotal, PhishTank, URLhaus.</li>
            </ul>
          </CardContent>
        </Card>
      </section>

      {/* How It Works & Technology */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ScanSearch className="h-5 w-5 text-secondary" />
              How Threat Detection Works
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 text-sm text-muted leading-relaxed">
            <p>
              Every link goes through URL normalization, SSRF policy validation, static 25-feature extraction,
              multi-signal heuristic inspection, ML probability estimation, and server-side threat intelligence lookup.
            </p>
            <p>
              No single weak attribute (like plain HTTP or a long path) is treated as proof of phishing. Low-risk
              links report <span className="font-medium text-foreground">&ldquo;No known threat detected&rdquo;</span>{" "}
              rather than claiming guaranteed safety.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Cpu className="h-5 w-5 text-secondary" />
              Platform Architecture
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {[
                "React 19",
                "TypeScript",
                "Tailwind CSS",
                "Recharts",
                "FastAPI",
                "Python 3.12",
                "Scikit-learn",
                "XGBoost",
                "PostgreSQL",
                "Supabase RLS",
                "Docker",
              ].map((tech) => (
                <Badge key={tech} variant="secondary">
                  {tech}
                </Badge>
              ))}
            </div>
            <div className="pt-1">
              <Button variant="outline" size="sm" asChild>
                <Link to="/about">
                  <ShieldCheck className="h-4 w-4 text-secondary" />
                  Read Detection Methodology
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
