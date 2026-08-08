"use client";

/* ───────────────────────────────────────────
   Dashboard — public recent scans.
   No auth check. No redirect. Anyone sees it.
   ─────────────────────────────────────────── */

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ScanHistory } from "@/components/scan/ScanHistory";
import type { ScanResult } from "@/types";
import { Shield, Plus } from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = () => {
    setLoading(true);
    setError(null);
    api.scan
      .history()
      .then((data) => {
        setScans(data);
        setError(null);
      })
      .catch(() => {
        setError("Failed to load scan history");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans();
  }, []);

  return (
    <div className="page-container py-8 sm:py-12 space-y-6">
      {error && (
        <div className="rounded-md bg-red-50 p-4 border border-red-200 flex justify-between items-center">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">{error}</h3>
            </div>
          </div>
          <button
            onClick={fetchScans}
            className="text-sm font-medium text-red-800 hover:text-red-900 underline focus:outline-none"
          >
            Retry
          </button>
        </div>
      )}

      <div>
        <h1 className="text-xl font-bold text-gray-900">Recent Scans</h1>
        <p className="text-sm text-gray-500 mt-1">Last 20 analyses run on this platform</p>
      </div>

      {!loading && scans.length === 0 ? (
        <div className="card py-16 flex flex-col items-center justify-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-brand-50 text-brand-600 mb-4">
            <Shield size={24} />
          </div>
          <h3 className="text-lg font-semibold text-gray-900">No scans yet</h3>
          <p className="text-sm text-gray-500 mt-1 max-w-sm mb-6">
            Submit your first file or URL to get started with threat analysis.
          </p>
          <Link href="/" className="btn-primary px-4 py-2 text-sm">
            <Plus size={16} className="mr-1.5" /> Start new scan
          </Link>
        </div>
      ) : (
        <ScanHistory scans={scans} loading={loading} />
      )}
    </div>
  );
}
