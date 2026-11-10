import { apiRequest } from "@/lib/apiClient";
import type {
  AuthTokenResponse,
  DashboardStats,
  HealthStatus,
  ModelStatus,
  PaginatedScansResponse,
  ScanReport,
  UserProfile,
} from "@/types/api";

export const api = {
  getHealth: () => apiRequest<HealthStatus>("/api/v1/health"),
  getModelStatus: () => apiRequest<ModelStatus>("/api/v1/model/status"),

  scanUrl: (url: string) =>
    apiRequest<ScanReport>("/api/v1/scan", {
      method: "POST",
      body: JSON.stringify({ url }),
    }),

  getScans: (params: {
    search?: string;
    risk_level?: string;
    domain?: string;
    date_from?: string;
    date_to?: string;
    page?: number;
    page_size?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.search) qs.set("search", params.search);
    if (params.risk_level && params.risk_level !== "ALL") qs.set("risk_level", params.risk_level);
    if (params.domain) qs.set("domain", params.domain);
    if (params.date_from) qs.set("date_from", params.date_from);
    if (params.date_to) qs.set("date_to", params.date_to);
    qs.set("page", String(params.page ?? 1));
    qs.set("page_size", String(params.page_size ?? 10));
    return apiRequest<PaginatedScansResponse>(`/api/v1/scans?${qs.toString()}`);
  },

  getScanDetail: (id: string) => apiRequest<ScanReport>(`/api/v1/scans/${id}`),

  deleteScan: (id: string) =>
    apiRequest<{ deleted: boolean; id: string }>(`/api/v1/scans/${id}`, {
      method: "DELETE",
    }),

  getDashboardStats: () => apiRequest<DashboardStats>("/api/v1/dashboard/stats"),

  registerLocal: (payload: { email: string; password: string; display_name: string }) =>
    apiRequest<AuthTokenResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  loginLocal: (payload: { email: string; password: string }) =>
    apiRequest<AuthTokenResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  resetPasswordLocal: (payload: { email: string; new_password?: string }) =>
    apiRequest<{ message: string }>("/api/v1/auth/reset-password", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getMyProfile: () => apiRequest<UserProfile>("/api/v1/auth/me"),

  updateMyProfile: (display_name: string) =>
    apiRequest<UserProfile>("/api/v1/auth/me", {
      method: "PATCH",
      body: JSON.stringify({ display_name }),
    }),
};

