import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, Plus, Search, Trash2 } from "lucide-react";
import { RiskBadge } from "@/components/RiskBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/context/ToastContext";
import { formatTimestamp } from "@/lib/utils";
import { api } from "@/services/api";

export function ScanHistoryPage() {
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const [domain, setDomain] = useState("");
  const [riskLevel, setRiskLevel] = useState("ALL");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [page, setPage] = useState(1);

  const statsQuery = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: api.getDashboardStats,
  });

  const historyQuery = useQuery({
    queryKey: ["scan-history", domain, riskLevel, dateFrom, dateTo, page],
    queryFn: () =>
      api.getScans({
        domain: domain || undefined,
        risk_level: riskLevel,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
        page,
        page_size: 10,
      }),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteScan,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["scan-history"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard-scans"] });
      notify({ title: "Scan deleted", description: "Record removed from your history.", variant: "success" });
    },
    onError: (err) => {
      notify({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "Could not delete scan record.",
        variant: "error",
      });
    },
  });

  const resetFilters = () => {
    setDomain("");
    setRiskLevel("ALL");
    setDateFrom("");
    setDateTo("");
    setPage(1);
  };

  const stats = statsQuery.data;

  const filterTabs = [
    { label: `All (${stats?.total_scans ?? historyQuery.data?.total ?? 0})`, value: "ALL" },
    { label: `Low (${stats?.low_risk_count ?? 0})`, value: "LOW" },
    { label: `Medium (${stats?.medium_risk_count ?? 0})`, value: "MEDIUM" },
    { label: `High (${stats?.high_risk_count ?? 0})`, value: "HIGH" },
    { label: `Critical (${stats?.critical_risk_count ?? 0})`, value: "CRITICAL" },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Header matching Screenshot 5 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight">My Scan History</h1>
            <Badge variant="secondary">{stats?.total_scans ?? historyQuery.data?.total ?? 0} Total</Badge>
          </div>
          <p className="text-sm text-muted">
            Track URL risk evaluations and review full security reports scoped to your account.
          </p>
        </div>

        <Button asChild>
          <Link to="/scanner">
            <Plus className="h-4 w-4" />
            New Scan
          </Link>
        </Button>
      </div>

      {/* Filter Pills + Search & Date Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {filterTabs.map((t) => (
            <button
              key={t.value}
              type="button"
              onClick={() => {
                setRiskLevel(t.value);
                setPage(1);
              }}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                riskLevel === t.value
                  ? "bg-primary text-primary-foreground border-primary"
                  : "bg-surface text-muted border-border hover:text-foreground"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="h-4 w-4 text-muted absolute left-3 top-3" />
            <Input
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setPage(1);
              }}
              placeholder="Filter by domain..."
              aria-label="Filter by domain"
              className="pl-9 w-48"
            />
          </div>
          <Input
            type="date"
            value={dateFrom}
            onChange={(e) => {
              setDateFrom(e.target.value);
              setPage(1);
            }}
            aria-label="Start date"
            className="w-36"
          />
          <Input
            type="date"
            value={dateTo}
            onChange={(e) => {
              setDateTo(e.target.value);
              setPage(1);
            }}
            aria-label="End date"
            className="w-36"
          />
          {(domain || riskLevel !== "ALL" || dateFrom || dateTo) && (
            <Button variant="outline" size="sm" onClick={resetFilters}>
              Reset
            </Button>
          )}
        </div>
      </div>

      {/* Table Card matching Screenshot 5 */}
      <Card className="overflow-hidden">
        <CardContent className="p-0">
          {historyQuery.isLoading ? (
            <div className="p-5 space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : historyQuery.isError ? (
            <div className="py-10 text-center text-sm text-red-600 dark:text-red-400">
              {historyQuery.error instanceof Error
                ? historyQuery.error.message
                : "Failed to load scan history."}
            </div>
          ) : historyQuery.data && historyQuery.data.items.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-[11px] font-semibold uppercase tracking-wider text-muted bg-surface-elevated border-b border-border">
                    <tr>
                      <th className="py-3 pl-5 pr-4">Ref ID</th>
                      <th className="py-3 pr-4">URL &amp; Date</th>
                      <th className="py-3 pr-4">Domain</th>
                      <th className="py-3 pr-4">Risk</th>
                      <th className="py-3 pr-4">Verdict</th>
                      <th className="py-3 pr-5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {historyQuery.data.items.map((row) => (
                      <tr key={row.id} className="hover:bg-surface-elevated/40">
                        <td className="py-3.5 pl-5 pr-4 font-mono text-xs font-medium text-muted whitespace-nowrap">
                          #{row.id.slice(0, 6).toUpperCase()}
                        </td>
                        <td className="py-3.5 pr-4 max-w-xs">
                          <p className="font-mono text-xs font-medium truncate text-foreground" title={row.original_url}>
                            {row.original_url}
                          </p>
                          <p className="text-[11px] text-muted mt-0.5">{formatTimestamp(row.created_at)}</p>
                        </td>
                        <td className="py-3.5 pr-4">
                          <Badge variant="secondary" className="font-mono text-[11px]">
                            {row.normalized_domain}
                          </Badge>
                        </td>
                        <td className="py-3.5 pr-4 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold tabular-nums">{row.risk_score}</span>
                            <RiskBadge level={row.risk_level} />
                          </div>
                        </td>
                        <td className="py-3.5 pr-4 max-w-xs">
                          <p className="text-xs text-muted truncate" title={row.verdict}>
                            {row.verdict}
                          </p>
                        </td>
                        <td className="py-3.5 pr-5 text-right whitespace-nowrap space-x-2">
                          <Button variant="outline" size="sm" asChild>
                            <Link to={`/scans/${row.id}`}>
                              <Eye className="h-3.5 w-3.5" />
                              View
                            </Link>
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-red-600 hover:bg-red-50 hover:text-red-700 border-red-200 dark:text-red-400 dark:border-red-500/30"
                            disabled={deleteMutation.isPending}
                            onClick={() => deleteMutation.mutate(row.id)}
                            aria-label={`Delete scan for ${row.normalized_domain}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            Delete
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between px-5 py-3.5 border-t border-border text-xs text-muted">
                <span>
                  Page {historyQuery.data.page} of {historyQuery.data.total_pages} ({historyQuery.data.total} scans)
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
                    disabled={page >= historyQuery.data.total_pages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="py-12 text-center space-y-3 text-sm text-muted">
              <p>No scan history found.</p>
              <Button size="sm" asChild>
                <Link to="/scanner">Scan a URL now</Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
