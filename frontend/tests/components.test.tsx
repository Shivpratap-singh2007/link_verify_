import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CircularRiskGauge } from "@/components/CircularRiskGauge";
import { ScanResultReport } from "@/components/ScanResultReport";
import { ScannerPage } from "@/pages/ScannerPage";
import { ThemeProvider } from "@/context/ThemeContext";
import { ToastProvider } from "@/context/ToastContext";
import { AuthProvider } from "@/context/AuthContext";
import { urlInputSchema } from "@/utils/urlValidation";
import type { ScanReport } from "@/types/api";

const mockScanReport: ScanReport = {
  id: null,
  persisted: false,
  submitted_url: "https://example.com",
  normalized_domain: "example.com",
  registered_domain: "example.com",
  scheme: "https",
  is_https: true,
  risk_score: 18,
  risk_level: "LOW",
  verdict: "No known threat detected.",
  model_confidence: 0.69,
  threat_intel_status: "not_configured",
  scan_status: "completed",
  ml_details: {
    model_loaded: true,
    model_name: "random_forest",
    model_version: "1.0.0",
    phishing_probability: 0.31,
    model_confidence: 0.69,
    predicted_label: "benign",
    status_message: "ML inference completed.",
  },
  detection_indicators: [],
  extracted_features: [
    { feature_name: "url_length", feature_value: "19.0", risk_contribution: 0 },
    { feature_name: "is_https", feature_value: "1.0", risk_contribution: 0 },
  ],
  threat_intelligence: [
    {
      provider: "google_safe_browsing",
      detection_status: "not_configured",
      message: "Threat intelligence service not configured.",
      details: {},
      cached: false,
    },
  ],
  evidence_breakdown: [
    {
      source: "Heuristic URL Engine",
      raw_score: 0,
      effective_weight: 0.41,
      status: "active",
      summary: "Evaluated 0 signals.",
    },
  ],
  recommendations: ["Confirm the domain spelling before entering credentials."],
  safety_disclaimer: "A low risk score does not guarantee that a website is safe.",
  scanned_at: "2026-11-10T10:00:00Z",
};

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <AuthProvider>
            <MemoryRouter>{ui}</MemoryRouter>
          </AuthProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  );
}

describe("URL validation schema", () => {
  it("accepts HTTP and HTTPS URLs and rejects unsafe schemes", () => {
    expect(urlInputSchema.safeParse({ url: "https://example.com" }).success).toBe(true);
    expect(urlInputSchema.safeParse({ url: "http://192.168.1.1/login/verify" }).success).toBe(true);
    expect(urlInputSchema.safeParse({ url: "javascript:alert(1)" }).success).toBe(false);
    expect(urlInputSchema.safeParse({ url: "not-a-url" }).success).toBe(false);
  });
});

describe("CircularRiskGauge", () => {
  it("renders score and risk classification accessibly", () => {
    render(<CircularRiskGauge score={82} riskLevel="CRITICAL" />);
    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Risk score 82 out of 100, classification CRITICAL/i }),
    ).toBeInTheDocument();
  });
});

describe("ScanResultReport", () => {
  it("displays non-absolute verdict, separate ML confidence, and not-configured threat intel message", () => {
    renderWithProviders(<ScanResultReport report={mockScanReport} />);
    expect(screen.getByText("No known threat detected.")).toBeInTheDocument();
    expect(screen.getByText(/does not guarantee that a website is safe/i)).toBeInTheDocument();
    expect(screen.getByText("69.0%")).toBeInTheDocument();
    expect(screen.getByText("Threat intelligence service not configured.")).toBeInTheDocument();
  });
});

describe("ScannerPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows validation error on invalid URL submission without calling API", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    renderWithProviders(<ScannerPage />);

    const input = screen.getByLabelText(/Target URL/i);
    fireEvent.change(input, { target: { value: "ftp://example.com" } });
    fireEvent.click(screen.getByRole("button", { name: /^Scan URL$/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/http:\/\/ or https:\/\//i);
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("populates URL from sample chip and clears input cleanly", () => {
    renderWithProviders(<ScannerPage />);
    fireEvent.click(screen.getByRole("button", { name: "https://example.com@evil.example" }));
    const input = screen.getByLabelText(/Target URL/i) as HTMLInputElement;
    expect(input.value).toBe("https://example.com@evil.example");

    fireEvent.click(screen.getByRole("button", { name: /Clear/i }));
    expect(input.value).toBe("");
  });

  it("submits scan when pressing Enter in the URL input", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(mockScanReport), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    renderWithProviders(<ScannerPage />);
    const input = screen.getByLabelText(/Target URL/i);
    fireEvent.change(input, { target: { value: "https://example.com" } });
    fireEvent.keyDown(input, { key: "Enter", code: "Enter" });

    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining("/api/v1/scan"),
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ url: "https://example.com" }),
        }),
      );
    });
  });
});

