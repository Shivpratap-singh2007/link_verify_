import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  CornerDownLeft,
  Cpu,
  Eye,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { RiskBadge } from "@/components/RiskBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/context/ToastContext";
import { formatTimestamp } from "@/lib/utils";
import { api } from "@/services/api";
import { urlInputSchema } from "@/utils/urlValidation";

const RISK_CHART_COLORS: Record<string, string> = {
  LOW: "#16A34A",
  MEDIUM: "#D97706",
  HIGH: "#EA580C",
  CRITICAL: "#DC2626",
};

const DONUT_COLORS: Record<string, string> = {
  LOW: "#16A34A",
  MEDIUM: "#0D9488",
  HIGH: "#0284C7",
  CRITICAL: "#2563EB",
};

export function DashboardPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const [quickUrl, setQuickUrl] = useState("");
  const [quickError, setQuickError] = useState<string | null>(null);
  const [quickScanning, setQuickScanning] = useState(false);

  const [daysWindow, setDaysWindow] = useState<7 | 14>(7);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [page, setPage] = useState(1);

  const statsQuery = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: api.getDashboardStats,
  });

  const modelQuery = useQuery({
    queryKey: ["model-status"],
    queryFn: api.getModelStatus,
    staleTime: 60_000,
  });

  const scansQuery = useQuery({
    queryKey: ["dashboard-scans", search, riskFilter, page],
    queryFn: () =>
      api.getScans({
        search: search || undefined,
        risk_level: riskFilter,
        page,
        page_size: 5,
      }),
  });

  const handleRefresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
    await queryClient.invalidateQueries({ queryKey: ["dashboard-scans"] });
    notify({ title: "Refreshed", description: "Dashboard telemetry updated.", variant: "info" });
  };

  const handleQuickScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setQuickError(null);
    const parsed = urlInputSchema.safeParse({ url: quickUrl });
    if (!parsed.success) {
      setQuickError(parsed.error.errors[0]?.message || "Invalid URL.");
      return;
    }

    setQuickScanning(true);
    try {
      const report = await api.scanUrl(parsed.data.url);
      await queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard-scans"] });
      await queryClient.invalidateQueries({ queryKey: ["scan-history"] });
      notify({
        title: `Scan complete (${report.risk_level})`,
        description: `Score: ${report.risk_score}/100`,
        variant: "success",
      });
      if (report.id) {
        navigate(`/scans/${report.id}`, { state: { report } });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Scan failed.";
      setQuickError(msg);
      notify({ title: "Quick scan failed", description: msg, variant: "error" });
    } finally {
      setQuickScanning(false);
    }
  };

  const stats = statsQuery.data;
  const totalScans = stats?.total_scans ?? 0;
  const lowPct = totalScans > 0 ? Math.round(((stats?.low_risk_count ?? 0) / totalScans) * 100) : 0;
  const elevatedCount = (stats?.high_risk_count ?? 0) + (stats?.critical_risk_count ?? 0);
  const mlAccuracyPct =
    modelQuery.data?.metrics?.accuracy !== undefined
      ? (modelQuery.data.metrics.accuracy * 100).toFixed(1)
      : null;

  const activitySlice = stats ? stats.scan_activity.slice(-daysWindow) : [];
  const donutData = (stats?.risk_distribution ?? []).filter((d) => d.count > 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Executive Header matching Screenshot 3 */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight">Security Executive Dashboard</h1>
            <Badge variant="low">Live ML Telemetry</Badge>
          </div>
          <p className="text-sm text-muted">
            Real-time URL risk breakdown, phishing classification telemetry, and persisted scan history.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-lg border border-border bg-surface p-0.5">
            <button
              type="button"
              onClick={() => setDaysWindow(7)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                daysWindow === 7 ? "bg-primary text-primary-foreground" : "text-muted hover:text-foreground"
              }`}
            >
              7 Days
            </button>
            <button
              type="button"
              onClick={() => setDaysWindow(14)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                daysWindow === 14 ? "bg-primary text-primary-foreground" : "text-muted hover:text-foreground"
              }`}
            >
              14 Days
            </button>
          </div>
          <Button variant="outline" size="sm" onClick={handleRefresh}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              setRiskFilter("CRITICAL");
              setPage(1);
            }}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            Critical Queue ({stats?.critical_risk_count ?? 0})
          </Button>
        </div>
      </div>

      {/* Quick Scan Bar with Enter Support */}
      <Card>
        <CardContent className="p-4">
          <form onSubmit={handleQuickScan} className="flex flex-col sm:flex-row gap-2.5" noValidate>
            <div className="relative flex-1">
              <Input
                type="text"
                inputMode="url"
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void handleQuickScan();
                  }
                }}
                placeholder="Quick scan: paste URL and press Enter (e.g. https://example.com/verify)"
                aria-label="Quick scan URL"
                className="font-mono text-sm pr-20"
              />
              <span className="hidden sm:inline-flex items-center gap-1 rounded border border-border bg-surface-elevated px-1.5 py-0.5 text-[10px] font-medium text-muted absolute right-2.5 top-2.5 pointer-events-none">
                <CornerDownLeft className="h-2.5 w-2.5" />
                Enter
              </span>
            </div>
            <Button type="submit" disabled={quickScanning}>
              <Plus className="h-4 w-4" />
              {quickScanning ? "Scanning..." : "Quick Scan"}
            </Button>
          </form>
          {quickError && (
            <p className="text-xs text-red-600 dark:text-red-400 mt-1.5" role="alert">
              {quickError}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Row 1: 4 Colored-Border Accent KPI Cards matching Screenshot 3 */}
      {statsQuery.isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Green-bordered card */}
          <Card className="border-2 border-emerald-500/80">
            <CardContent className="p-5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">Low-Risk Clearance Rate</span>
                <Badge variant="low">{totalScans > 0 ? "Active" : "Idle"}</Badge>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-emerald-600 dark:text-emerald-400 tabular-nums">
                  {lowPct}%
                </span>
                <span className="text-xs text-muted">low-risk share</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-surface-elevated overflow-hidden">
                <div className="h-full bg-emerald-600 rounded-full" style={{ width: `${lowPct}%` }} />
              </div>
              <p className="text-[11px] text-muted">{stats?.low_risk_count ?? 0} low-risk URLs recorded</p>
            </CardContent>
          </Card>

          {/* Blue-bordered card */}
          <Card className="border-2 border-blue-500/85">
            <CardContent className="p-5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">ML Classifier Performance</span>
                <Cpu className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-blue-600 dark:text-blue-400 tabular-nums">
                  {mlAccuracyPct ? `${mlAccuracyPct}%` : "N/A"}
                </span>
                <span className="text-xs text-muted">test accuracy</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-surface-elevated overflow-hidden">
                <div
                  className="h-full bg-blue-600 rounded-full"
                  style={{ width: `${mlAccuracyPct ? Number(mlAccuracyPct) : 0}%` }}
                />
              </div>
              <p className="text-[11px] text-muted">
                Model: {modelQuery.data?.model_name || "Not trained"}
              </p>
            </CardContent>
          </Card>

          {/* Cyan-bordered card */}
          <Card className="border-2 border-cyan-500/85">
            <CardContent className="p-5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">Total Static URL Scans</span>
                <ShieldCheck className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-foreground tabular-nums">{totalScans}</span>
                <span className="text-xs text-muted">persisted checks</span>
              </div>
              <p className="text-[11px] text-emerald-700 dark:text-emerald-400">
                25 lexical &amp; domain features per scan
              </p>
              <p className="text-[11px] text-muted">Zero-execution SSRF-protected analysis</p>
            </CardContent>
          </Card>

          {/* Amber-bordered card */}
          <Card className="border-2 border-amber-400/90">
            <CardContent className="p-5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-foreground">Elevated Risk Alerts</span>
                <Activity className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-foreground tabular-nums">{elevatedCount}</span>
                <span className="text-xs text-muted">high + critical</span>
              </div>
              <div className="flex items-center justify-between text-[11px] pt-1">
                <span className="text-orange-600 dark:text-orange-400 font-medium">
                  High: {stats?.high_risk_count ?? 0}
                </span>
                <span className="text-red-600 dark:text-red-400 font-medium">
                  Critical: {stats?.critical_risk_count ?? 0}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Row 2: Compact 6-Card Metric Strip matching Screenshot 3 */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "TOTAL SCANS", value: totalScans, sub: "Persisted URLs", cls: "text-foreground" },
          { label: "LOW RISK", value: stats?.low_risk_count ?? 0, sub: "Score 0–24", cls: "text-emerald-600 dark:text-emerald-400" },
          { label: "MEDIUM RISK", value: stats?.medium_risk_count ?? 0, sub: "Score 25–49", cls: "text-amber-600 dark:text-amber-400" },
          { label: "HIGH RISK", value: stats?.high_risk_count ?? 0, sub: "Score 50–74", cls: "text-orange-600 dark:text-orange-400" },
          { label: "CRITICAL RISK", value: stats?.critical_risk_count ?? 0, sub: "Score 75–100", cls: "text-red-600 dark:text-red-400" },
          { label: "AVG RISK SCORE", value: stats?.average_risk_score ?? 0, sub: "Out of 100", cls: "text-secondary" },
        ].map((m) => (
          <Card key={m.label}>
            <CardContent className="p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">{m.label}</p>
              <p className={`text-2xl font-bold mt-1 tabular-nums ${m.cls}`}>{m.value}</p>
              <p className="text-[11px] text-muted mt-0.5">{m.sub}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Row 3: Charts matching Screenshots 1 & 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Scan Trends ({daysWindow} Days)</CardTitle>
              <CardDescription>Daily scan activity</CardDescription>
            </div>
            <Badge variant="secondary">Dynamic Timeline</Badge>
          </CardHeader>
          <CardContent className="h-64">
            {stats && stats.total_scans > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activitySlice}>
                  <defs>
                    <linearGradient id="scanAreaBlue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563EB" stopOpacity={0.28} />
                      <stop offset="95%" stopColor="#2563EB" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis
                    dataKey="date"
                    stroke="var(--text-muted)"
                    fontSize={11}
                    tickFormatter={(v: string) => v.slice(5)}
                  />
                  <YAxis allowDecimals={false} stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--bg-surface)",
                      borderColor: "var(--border-subtle)",
                      color: "var(--text-primary)",
                      borderRadius: "8px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    name="Total Scans"
                    stroke="#2563EB"
                    strokeWidth={2.5}
                    fill="url(#scanAreaBlue)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-muted text-center px-4">
                Run a scan to visualize daily activity trends.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Risk Levels Distribution</CardTitle>
              <CardDescription>Count by severity tier</CardDescription>
            </div>
            <Badge variant="secondary">Triage Breakdown</Badge>
          </CardHeader>
          <CardContent className="h-64">
            {stats && stats.total_scans > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.risk_distribution}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="risk_level" stroke="var(--text-muted)" fontSize={11} />
                  <YAxis allowDecimals={false} stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--bg-surface)",
                      borderColor: "var(--border-subtle)",
                      color: "var(--text-primary)",
                      borderRadius: "8px",
                    }}
                  />
                  <Bar dataKey="count" name="Scans" radius={[6, 6, 0, 0]}>
                    {stats.risk_distribution.map((entry) => (
                      <Cell
                        key={entry.risk_level}
                        fill={RISK_CHART_COLORS[entry.risk_level] || "#2563EB"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-muted text-center px-4">
                No scans yet. Submit a URL to view risk distribution.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Verdict Share</CardTitle>
              <CardDescription>Proportion by risk tier</CardDescription>
            </div>
            <Badge variant="secondary">Donut Breakdown</Badge>
          </CardHeader>
          <CardContent className="h-64 flex flex-col">
            {donutData.length > 0 ? (
              <>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={donutData}
                        dataKey="count"
                        nameKey="risk_level"
                        innerRadius={45}
                        outerRadius={72}
                        paddingAngle={3}
                      >
                        {donutData.map((entry) => (
                          <Cell
                            key={entry.risk_level}
                            fill={DONUT_COLORS[entry.risk_level] || "#2563EB"}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "var(--bg-surface)",
                          borderColor: "var(--border-subtle)",
                          color: "var(--text-primary)",
                          borderRadius: "8px",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap justify-center gap-3 text-xs pt-1">
                  {donutData.map((d) => (
                    <span key={d.risk_level} className="inline-flex items-center gap-1.5 text-muted">
                      <span
                        className="h-2.5 w-2.5 rounded-sm"
                        style={{ backgroundColor: DONUT_COLORS[d.risk_level] || "#2563EB" }}
                      />
                      {d.risk_level} ({d.count})
                    </span>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-muted text-center px-4">
                No proportional scan data yet.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 4: Recent Scans Table matching Screenshot 1 & 4 */}
      <Card className="overflow-hidden">
        <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <CardTitle>Recent URL Scans</CardTitle>
            <Badge variant="secondary">{scansQuery.data?.total ?? 0} Records</Badge>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="h-4 w-4 text-muted absolute left-3 top-3" />
              <Input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Search scans..."
                className="pl-9 w-56"
              />
            </div>
            <select
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value);
                setPage(1);
              }}
              aria-label="Filter by risk level"
              className="h-10 rounded-lg border border-border bg-surface px-3 text-sm text-foreground"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {scansQuery.isLoading ? (
            <div className="p-5 space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : scansQuery.data && scansQuery.data.items.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-[11px] font-semibold uppercase tracking-wider text-muted bg-surface-elevated border-y border-border">
                    <tr>
                      <th className="py-3 pl-5 pr-4">Scan ID</th>
                      <th className="py-3 pr-4">URL &amp; Domain</th>
                      <th className="py-3 pr-4">Score</th>
                      <th className="py-3 pr-4">Risk Level</th>
                      <th className="py-3 pr-4">Scanned</th>
                      <th className="py-3 pr-5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {scansQuery.data.items.map((item) => (
                      <tr key={item.id} className="hover:bg-surface-elevated/50">
                        <td className="py-3.5 pl-5 pr-4 font-mono text-xs font-semibold text-secondary whitespace-nowrap">
                          #{item.id.slice(0, 6).toUpperCase()}
                        </td>
                        <td className="py-3.5 pr-4 max-w-xs">
                          <p className="font-mono text-xs font-medium truncate text-foreground" title={item.original_url}>
                            {item.original_url}
                          </p>
                          <p className="text-xs text-muted">{item.normalized_domain}</p>
                        </td>
                        <td className="py-3.5 pr-4 font-mono font-semibold tabular-nums">
                          {item.risk_score}/100
                        </td>
                        <td className="py-3.5 pr-4">
                          <RiskBadge level={item.risk_level} />
                        </td>
                        <td className="py-3.5 pr-4 text-xs text-muted whitespace-nowrap">
                          {formatTimestamp(item.created_at)}
                        </td>
                        <td className="py-3.5 pr-5 text-right">
                          <Button variant="outline" size="sm" asChild>
                            <Link to={`/scans/${item.id}`}>
                              <Eye className="h-3.5 w-3.5" />
                              View Report
                            </Link>
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between px-5 py-3.5 border-t border-border text-xs text-muted">
                <span>
                  Page {scansQuery.data.page} of {scansQuery.data.total_pages} ({scansQuery.data.total} total)
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= scansQuery.data.total_pages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="py-10 text-center space-y-2 text-sm text-muted">
              <p>No scan records match your current filters.</p>
              <Button variant="outline" size="sm" asChild>
                <Link to="/scanner">Run your first URL scan</Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
