import { useQuery } from "@tanstack/react-query";
import { Cpu, Lock, ShieldCheck, Layers } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/services/api";

export function AboutPage() {
  const modelQuery = useQuery({
    queryKey: ["model-status"],
    queryFn: api.getModelStatus,
  });

  const model = modelQuery.data;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-10 space-y-8">
      <div className="space-y-2">
        <Badge variant="default">About LINK VERIFY AI</Badge>
        <h1 className="text-3xl font-bold tracking-tight">
          Transparent Phishing Intelligence &amp; Static URL Analysis
        </h1>
        <p className="text-muted text-sm sm:text-base leading-relaxed">
          LINK VERIFY AI is a cybersecurity analysis platform built to inspect suspicious links before users open
          them, combining deterministic URL feature engineering, supervised machine learning, and server-side threat
          intelligence feeds.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              Why Phishing Detection Matters
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted space-y-2.5 leading-relaxed">
            <p>
              Credential harvesting and deceptive links remain one of the most common initial access vectors for
              account compromise and financial fraud.
            </p>
            <p>
              Attackers increasingly combine trusted-looking subdomains, URL shorteners, <code className="font-mono">@</code>{" "}
              authority spoofing, and Punycode homographs to trick users at a glance. Early pre-click verification gives
              analysts and everyday users clear evidence instead of guesswork.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-secondary" />
              Zero-Execution Security Model
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted space-y-2.5 leading-relaxed">
            <p>
              Submitted URLs are never fetched, rendered, or executed by our backend. Analysis relies strictly on static
              URL parsing and external reputation APIs, preventing SSRF and drive-by payload execution.
            </p>
            <p>
              When external API keys are not configured, providers transparently report{" "}
              <span className="text-foreground font-medium">&ldquo;Threat intelligence service not configured&rdquo;</span>{" "}
              rather than fabricating results.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5 text-primary" />
            Machine Learning &amp; Risk Aggregation Pipeline
          </CardTitle>
          <CardDescription>
            Live status and evaluated test performance retrieved directly from the backend model registry.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted">
          <p>
            The detection engine extracts {model?.feature_names.length ?? 25} lexical and structural URL features,
            evaluates multi-signal heuristic rules (never treating any single weak signal like HTTP or URL length as
            proof of maliciousness), runs a trained classifier when available, and keeps{" "}
            <strong className="text-foreground">ML model confidence</strong> separate from the{" "}
            <strong className="text-foreground">0–100 risk score</strong>.
          </p>

          {model?.model_loaded && model.metrics ? (
            <div className="rounded-xl border border-border bg-surface-elevated/60 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-foreground">
                  Active Classifier: <span className="font-mono text-secondary">{model.model_name}</span> (v
                  {model.model_version})
                </span>
                <span className="text-xs">{model.dataset?.name}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
                {[
                  ["Accuracy", model.metrics.accuracy],
                  ["Precision", model.metrics.precision],
                  ["Recall", model.metrics.recall],
                  ["F1-Score", model.metrics.f1_score],
                  ["ROC-AUC", model.metrics.roc_auc],
                ].map(([label, val]) => (
                  <div key={String(label)} className="rounded-lg border border-border bg-surface p-2.5">
                    <div className="text-[11px] text-muted">{label}</div>
                    <div className="font-mono font-semibold text-foreground mt-0.5">
                      {typeof val === "number" ? `${(val * 100).toFixed(2)}%` : "—"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-border bg-background/60 p-4 text-xs">
              ML model status: {model?.message ?? "Checking model availability..."}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-secondary" />
            Technology &amp; Engineering Scope
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted leading-relaxed">
          <p>
            Built with React 19, TypeScript, Tailwind CSS, TanStack Query, Recharts, FastAPI, SQLAlchemy 2.0,
            Scikit-learn, XGBoost, and PostgreSQL / Supabase Row Level Security.
          </p>
          <p>
            Project Engineering Team: Maintained as an open security engineering platform focused on reproducible ML
            evaluation, transparent scoring, and strict input/SSRF safety controls.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

