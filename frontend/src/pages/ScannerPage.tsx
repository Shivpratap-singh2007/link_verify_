import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { ClipboardPaste, CornerDownLeft, Eraser, ScanSearch, ShieldCheck } from "lucide-react";
import { ScanProgress } from "@/components/ScanProgress";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useToast } from "@/context/ToastContext";
import { api } from "@/services/api";
import { urlInputSchema, type UrlInputFormValues } from "@/utils/urlValidation";

const EXAMPLE_TEST_URLS = [
  "https://example.com",
  "http://192.168.1.1/login/verify",
  "https://example.com@evil.example",
  "https://example.com/login/verify",
];

export function ScannerPage() {
  const navigate = useNavigate();
  const { notify } = useToast();
  const [scanning, setScanning] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<UrlInputFormValues>({
    resolver: zodResolver(urlInputSchema),
    defaultValues: { url: "" },
  });

  const currentUrl = watch("url");

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setValue("url", text.trim(), { shouldValidate: true });
        setApiError(null);
      }
    } catch {
      notify({
        title: "Clipboard access unavailable",
        description: "Paste manually using Ctrl+V or Cmd+V, then press Enter.",
        variant: "info",
      });
    }
  };

  const handleClear = () => {
    setValue("url", "", { shouldValidate: false });
    setApiError(null);
  };

  const onSubmit = async (values: UrlInputFormValues) => {
    setApiError(null);
    setScanning(true);
    try {
      const report = await api.scanUrl(values.url);
      notify({
        title: `Analysis complete (${report.risk_level})`,
        description: `Risk score: ${report.risk_score}/100`,
        variant: report.risk_level === "LOW" ? "success" : "info",
      });
      if (report.persisted && report.id) {
        navigate(`/scans/${report.id}`, { state: { report } });
      } else {
        navigate("/scan-result", { state: { report } });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to complete scan.";
      setApiError(message);
      notify({ title: "Scan error", description: message, variant: "error" });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-10 space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight flex items-center gap-2.5">
          <ScanSearch className="h-7 w-7 text-secondary" />
          URL Security Scanner
        </h1>
        <p className="text-sm text-muted">
          Enter or paste any HTTP/HTTPS URL and press{" "}
          <kbd className="font-mono px-1.5 py-0.5 rounded bg-surface-elevated border border-border text-xs">
            Enter
          </kbd>{" "}
          or click Scan URL for immediate static threat analysis.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Analyze Suspicious Link</CardTitle>
          <CardDescription>
            Target URLs are validated strictly and analyzed statically without executing scripts or opening connections to the target.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
            <div className="space-y-2">
              <label htmlFor="scanner-url-input" className="text-xs font-medium uppercase tracking-wider text-muted">
                Target URL (HTTP / HTTPS)
              </label>
              <div className="relative">
                <Input
                  id="scanner-url-input"
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://example.com/login/verify"
                  className="h-11 pr-28 font-mono text-sm"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      void handleSubmit(onSubmit)();
                    }
                  }}
                  {...register("url")}
                />
                <span className="hidden sm:inline-flex items-center gap-1 rounded border border-border bg-surface-elevated px-2 py-0.5 text-[11px] font-medium text-muted absolute right-2.5 top-2.5 pointer-events-none">
                  <CornerDownLeft className="h-3 w-3" />
                  Press Enter
                </span>
              </div>
              {errors.url && (
                <p className="text-xs text-red-600 dark:text-red-400" role="alert">
                  {errors.url.message}
                </p>
              )}
              {apiError && (
                <div
                  className="rounded-lg border border-red-200 bg-red-50 text-red-700 dark:border-red-500/30 dark:bg-red-500/10 p-3 text-xs dark:text-red-400"
                  role="alert"
                >
                  {apiError}
                </div>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <Button type="submit" disabled={scanning} className="min-w-36">
                {scanning ? "Scanning..." : "Scan URL"}
              </Button>
              <Button type="button" variant="outline" onClick={handlePaste} disabled={scanning}>
                <ClipboardPaste className="h-4 w-4" />
                Paste URL
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleClear}
                disabled={scanning || !currentUrl}
              >
                <Eraser className="h-4 w-4" />
                Clear
              </Button>
            </div>
          </form>

          <ScanProgress active={scanning} />

          <div className="pt-3 border-t border-border space-y-2">
            <p className="text-xs font-medium text-muted">
              Sample test inputs (click to populate, then press Enter or Scan URL):
            </p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_TEST_URLS.map((sample) => (
                <button
                  key={sample}
                  type="button"
                  disabled={scanning}
                  onClick={() => {
                    setValue("url", sample, { shouldValidate: true });
                    setApiError(null);
                  }}
                  className="text-xs font-mono px-2.5 py-1.5 rounded-md border border-border bg-surface-elevated hover:border-secondary hover:text-secondary transition-colors text-left"
                >
                  {sample}
                </button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="rounded-xl border border-border bg-surface p-4 flex items-start gap-3 text-xs text-muted">
        <ShieldCheck className="h-5 w-5 text-secondary shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          SSRF &amp; Safety Protection: Localhost, loopback, link-local, and cloud metadata endpoints are rejected.
          Non-HTTP schemes such as <code className="font-mono text-foreground">javascript:</code> or{" "}
          <code className="font-mono text-foreground">file:</code> are blocked.
        </p>
      </div>
    </div>
  );
}
