/* ───────────────────────────────────────────
   ThreatScope AI — API client
   Scan functions only. No auth. No tokens.
   ─────────────────────────────────────────── */

import type { JobResponse, ScanResult, PlatformStats, HealthStatus } from "@/types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(
      typeof err.detail === "string"
        ? err.detail
        : Array.isArray(err.detail)
          ? err.detail.map((d: { msg: string }) => d.msg).join(", ")
          : `HTTP ${res.status}`,
    );
  }
  return res.json() as Promise<T>;
}

export const api = {
  async stats(): Promise<PlatformStats> {
    const res = await fetch(`${BASE}/api/stats`);
    return handleResponse<PlatformStats>(res);
  },

  async health(): Promise<HealthStatus> {
    const res = await fetch(`${BASE}/api/health`);
    return handleResponse<HealthStatus>(res);
  },

  scan: {
    async file(file: File): Promise<JobResponse> {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${BASE}/api/scan/file`, {
        method: "POST",
        body: form,
      });
      return handleResponse<JobResponse>(res);
    },

    async url(url: string): Promise<JobResponse> {
      const res = await fetch(`${BASE}/api/scan/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      return handleResponse<JobResponse>(res);
    },

    async ip(target: string): Promise<JobResponse> {
      const res = await fetch(`${BASE}/api/scan/ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      return handleResponse<JobResponse>(res);
    },

    async result(jobId: string): Promise<ScanResult> {
      const res = await fetch(`${BASE}/api/scan/${jobId}`);
      return handleResponse<ScanResult>(res);
    },

    async history(): Promise<ScanResult[]> {
      const res = await fetch(`${BASE}/api/scan/history`);
      const data = await handleResponse<{ scans: ScanResult[] }>(res);
      return data.scans;
    },
  },
};
