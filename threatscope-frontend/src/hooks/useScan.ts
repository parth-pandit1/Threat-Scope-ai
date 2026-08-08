"use client";

/* ───────────────────────────────────────────
   useScan — polls GET /api/scan/{jobId} every
   3s until status is completed or failed.
   ─────────────────────────────────────────── */

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { ScanResult } from "@/types";

interface UseScanReturn {
  scan: ScanResult | null;
  loading: boolean;
  error: string | null;
}

export function useScan(jobId: string): UseScanReturn {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchScan = useCallback(async () => {
    try {
      const data = await api.scan.result(jobId);
      setScan(data);
      if (data.status === "completed" || data.status === "failed") {
        if (intervalRef.current) clearInterval(intervalRef.current);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
      if (intervalRef.current) clearInterval(intervalRef.current);
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setScan(null);
    fetchScan();
    intervalRef.current = setInterval(fetchScan, 3000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchScan]);

  return { scan, loading, error };
}
