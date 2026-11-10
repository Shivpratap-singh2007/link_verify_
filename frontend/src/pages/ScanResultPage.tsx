import { Link, useLocation, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, ScanSearch } from "lucide-react";
import { ScanResultReport } from "@/components/ScanResultReport";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/services/api";
import type { ScanReport } from "@/types/api";

export function ScanResultPage() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const stateReport = (location.state as { report?: ScanReport } | null)?.report;

  const query = useQuery({
    queryKey: ["scan-detail", id],
    queryFn: () => api.getScanDetail(id!),
    enabled: Boolean(id) && !stateReport,
  });

  const report = stateReport ?? query.data;

  if (id && query.isLoading && !report) {
    return (
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-10 space-y-6">
        <Skeleton className="h-9 w-36" />
        <Skeleton className="h-64 w-full" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Skeleton className="h-48" />
          <Skeleton className="h-48" />
        </div>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-16">
        <Card className="border-red-500/30">
          <CardContent className="p-8 text-center space-y-4">
            <AlertCircle className="h-10 w-10 text-red-400 mx-auto" />
            <h1 className="text-xl font-semibold">Unable to Load Scan Report</h1>
            <p className="text-sm text-muted">
              {query.error instanceof Error
                ? query.error.message
                : "The scan report could not be retrieved or does not belong to your account."}
            </p>
            <Button asChild>
              <Link to="/scanner">Return to Scanner</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-16">
        <Card>
          <CardContent className="p-8 text-center space-y-4">
            <ScanSearch className="h-10 w-10 text-primary mx-auto" />
            <h1 className="text-xl font-semibold">No Scan Report Selected</h1>
            <p className="text-sm text-muted">
              Submit a URL in the scanner to generate a detailed phishing and threat intelligence report.
            </p>
            <Button asChild>
              <Link to="/scanner">Go to URL Scanner</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-10">
      <ScanResultReport report={report} />
    </div>
  );
}

