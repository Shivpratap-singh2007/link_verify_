export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface DetectionIndicator {
  code: string;
  title: string;
  severity: string;
  contribution: number;
  description: string;
  evidence: string;
}

export interface ExtractedFeature {
  feature_name: string;
  feature_value: string;
  risk_contribution: number;
}

export interface ThreatIntelEntry {
  provider: string;
  detection_status: string;
  message: string;
  details: Record<string, unknown>;
  cached: boolean;
}

export interface EvidenceBreakdown {
  source: string;
  raw_score: number | null;
  effective_weight: number;
  status: string;
  summary: string;
}

export interface MLDetails {
  model_loaded: boolean;
  model_name: string | null;
  model_version: string | null;
  phishing_probability: number | null;
  model_confidence: number | null;
  predicted_label: string | null;
  status_message: string;
}

export interface ScanReport {
  id: string | null;
  persisted: boolean;
  submitted_url: string;
  normalized_domain: string;
  registered_domain: string;
  scheme: string;
  is_https: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  verdict: string;
  model_confidence: number | null;
  threat_intel_status: string;
  scan_status: string;
  ml_details: MLDetails;
  detection_indicators: DetectionIndicator[];
  extracted_features: ExtractedFeature[];
  threat_intelligence: ThreatIntelEntry[];
  evidence_breakdown: EvidenceBreakdown[];
  recommendations: string[];
  safety_disclaimer: string;
  scanned_at: string;
}

export interface ScanSummary {
  id: string;
  original_url: string;
  normalized_domain: string;
  risk_score: number;
  risk_level: RiskLevel;
  model_confidence: number | null;
  verdict: string;
  scan_status: string;
  created_at: string;
}

export interface PaginatedScansResponse {
  items: ScanSummary[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface RiskDistributionItem {
  risk_level: string;
  count: number;
}

export interface DailyActivityItem {
  date: string;
  total: number;
  high_or_critical: number;
}

export interface DashboardStats {
  total_scans: number;
  low_risk_count: number;
  medium_risk_count: number;
  high_risk_count: number;
  critical_risk_count: number;
  average_risk_score: number;
  risk_distribution: RiskDistributionItem[];
  scan_activity: DailyActivityItem[];
  recent_scans: ScanSummary[];
}

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
  database_engine: string;
  auth_mode: string;
  ml_model_loaded: boolean;
}

export interface ModelStatus {
  model_loaded: boolean;
  status: string;
  message: string;
  model_name: string | null;
  model_version: string | null;
  trained_at: string | null;
  dataset: {
    name?: string;
    source_url?: string;
    total_evaluated_rows?: number;
    train_rows?: number;
    validation_rows?: number;
    test_rows?: number;
    phishing_rate_test?: number;
  } | null;
  feature_names: string[];
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
    roc_auc?: number;
    confusion_matrix?: {
      tn: number;
      fp: number;
      fn: number;
      tp: number;
    };
  } | null;
}

export interface UserProfile {
  id: string;
  email: string;
  display_name: string;
  auth_provider: string;
  created_at: string;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  auth_mode: string;
  user: UserProfile;
}

