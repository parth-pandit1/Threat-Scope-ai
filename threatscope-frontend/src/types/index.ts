/* ───────────────────────────────────────────
   ThreatScope AI — TypeScript type definitions
   Matches the Phase 2 backend response schemas.
   No auth types — platform is open.
   ─────────────────────────────────────────── */

export interface PlatformStats {
  total_scans: number;
  malicious_scans: number;
  start_date: string;
}

export interface HealthStatus {
  status: string;
  postgres: string;
  redis: string;
  ollama: string;
  minio: string;
  yara: {
    loaded: boolean;
    rule_count: number;
    last_updated: string;
  };
}

/* ── Scan ─────────────────────────────────── */

export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type ScanType = "file" | "url";
export type Verdict = "clean" | "low_risk" | "suspicious" | "malicious";

export interface JobResponse {
  job_id: string;
  status: ScanStatus;
}

export interface ScanResult {
  job_id: string;
  scan_type: ScanType;
  target: string;
  status: ScanStatus;
  file_hash_md5: string | null;
  file_hash_sha256: string | null;
  threat_score: number | null;
  verdict: Verdict | null;
  result: AnalysisResult | null;
  created_at: string;
  completed_at: string | null;
}

/* ── Analysis Result (Phase 2) ────────────── */

export interface AnalysisResult {
  file_info?: FileInfo;
  entropy?: EntropyResult;
  pe_analysis?: PEAnalysis;
  strings?: StringsResult;
  yara?: YARAResult;
  url_info?: URLInfo;
  whois?: Record<string, unknown>;
  dns?: Record<string, unknown>;
  ssl?: SSLResult;
  screenshot?: ScreenshotResult;
  page_intel?: PageIntel;
  iocs?: IOCResult;
  virustotal?: VTResult;
  threat_score_breakdown?: ThreatScoreBreakdown;
  ai_explanation?: AIExplanation;
  analysis_timestamp?: string;
}

/* ── File / URL Info ─────────────────────── */

export interface FileInfo {
  md5: string;
  sha256: string;
  size_bytes: number;
  minio_object?: string;
}

export interface URLInfo {
  original_url: string;
  domain: string;
  scheme: string;
  path: string;
}

/* ── Entropy ──────────────────────────────── */

export interface EntropyResult {
  value: number;
  entropy_score: number;
  entropy_label: "normal" | "elevated" | "high" | "very_high";
  entropy_note: string;
  section_entropy: SectionEntropy[];
}

export interface SectionEntropy {
  name: string;
  entropy: number;
  size: number;
}

/* ── PE Analysis ──────────────────────────── */

export interface PEAnalysis {
  is_pe: boolean;
  machine_type?: string;
  compile_timestamp?: string | null;
  is_timestamp_suspicious?: boolean;
  subsystem?: string;
  is_dll?: boolean;
  is_driver?: boolean;
  sections?: PESection[];
  suspicious_sections?: { name: string; reasons: string[] }[];
  imports?: Record<string, string[]>;
  suspicious_imports?: string[];
  exports?: string[];
  has_resources?: boolean;
  resource_types?: string[];
  overlay_size?: number;
  pe_score: number;
  error?: string;
}

export interface PESection {
  name: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  is_executable: boolean;
  is_writable: boolean;
  flags: string;
}

/* ── Strings ──────────────────────────────── */

export interface StringsResult {
  total_count: number;
  suspicious_strings: Record<string, string[]>;
  suspicious_count: number;
  string_score: number;
  has_base64_payload: boolean;
  decoded_base64: string[];
}

/* ── YARA ─────────────────────────────────── */

export interface YARAResult {
  yara_available: boolean;
  matches: YARAMatch[];
  match_count: number;
  yara_score: number;
  malware_families: string[];
  highest_severity: string;
  error?: string;
}

export interface YARAMatch {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string>;
  strings_matched: string[];
  severity: string;
  source_repo?: string;
}

/* ── IOC ──────────────────────────────────── */

export interface IOCResult {
  ipv4: string[];
  ipv6: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  hashes: { md5: string[]; sha1: string[]; sha256: string[]; sha512: string[] };
  registry_keys: string[];
  file_paths: string[];
  mutexes: string[];
  crypto_wallets: { bitcoin: string[]; ethereum: string[] };
  cves: string[];
  mitre_techniques: string[];
  total_ioc_count: number;
}

/* ── VirusTotal ───────────────────────────── */

export interface VTResult {
  vt_available: boolean;
  vt_found?: boolean;
  vt_malicious_count?: number;
  vt_suspicious_count?: number;
  vt_total_engines?: number;
  vt_popular_threat_name?: string;
  vt_rate_limited?: boolean;
  vt_report_url?: string;
  error?: string;
}

/* ── SSL ──────────────────────────────────── */

export interface SSLResult {
  ssl_available: boolean;
  is_valid?: boolean;
  is_expired?: boolean;
  is_self_signed?: boolean;
  days_until_expiry?: number;
  issued_to?: string;
  issued_by?: string;
  issuer_org?: string;
  valid_from?: string;
  valid_until?: string;
  san_domains?: string[];
  tls_version?: string;
  ssl_score: number;
  ssl_notes: string[];
  error?: string;
}

/* ── Screenshot ───────────────────────────── */

export interface ScreenshotResult {
  screenshot_available: boolean;
  screenshot_path?: string | null;
  screenshot_url?: string | null;
  page_title?: string;
  final_url?: string;
  redirect_count?: number;
  redirect_chain?: string[];
  page_load_time_ms?: number;
  error?: string | null;
}

export interface PageIntel {
  page_intel_available: boolean;
  hidden_iframes?: string[];
  external_scripts?: string[];
  form_actions?: string[];
  has_password_field?: boolean;
  has_login_form?: boolean;
  page_text_sample?: string;
  error?: string;
}

/* ── Threat Score ─────────────────────────── */

export interface ThreatScoreBreakdown {
  score: number;
  verdict: Verdict;
  verdict_label: string;
  verdict_color: string;
  breakdown: Record<string, SignalScore>;
  reasons: string[];
  top_threat: string | null;
  scan_type: ScanType;
}

export interface SignalScore {
  score: number;
  max: number;
  detail: string;
}

/* ── AI Explanation ───────────────────────── */

export interface AIExplanation {
  ai_available: boolean;
  explanation?: string | null;
  mitre_techniques?: MITRETechnique[];
  recommended_actions?: string[];
  confidence?: "low" | "medium" | "high";
  model_used?: string;
  error?: string | null;
}

export interface MITRETechnique {
  id: string;
  name: string;
  tactic: string;
}
