"use client";

import Link from "next/link";
import { File, Globe, Server, Loader2, CheckCircle2, XCircle, Clock, Search } from "lucide-react";
import type { ScanResult } from "@/types";
import { timeAgo, shortHash } from "@/lib/utils";
import { VerdictBadge } from "@/components/ui/VerdictBadge";

interface Props {
  scans: ScanResult[];
  loading: boolean;
}

const statusIcons = {
  queued: <Clock size={14} className="text-gray-400" />,
  running: <Loader2 size={14} className="text-brand-500 animate-spin" />,
  completed: <CheckCircle2 size={14} className="text-emerald-500" />,
  failed: <XCircle size={14} className="text-red-500" />,
};

const typeIcons = {
  file: <File size={16} />,
  url: <Globe size={16} />,
  ip: <Server size={16} />,
};

export function ScanHistory({ scans, loading }: Props) {
  if (loading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="skeleton h-[68px] rounded-xl" />
        ))}
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="card flex flex-col items-center py-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-gray-50 mb-3">
          <Search size={20} className="text-gray-400" />
        </div>
        <p className="text-sm font-medium text-gray-600">No scans yet</p>
        <p className="text-xs text-gray-400 mt-1">Submitted scans will appear here</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {scans.map((scan) => (
        <ScanRow key={scan.job_id} scan={scan} />
      ))}
    </div>
  );
}

function ScanRow({ scan }: { scan: ScanResult }) {
  return (
    <Link
      href={`/scan/${scan.job_id}`}
      className="card flex items-center gap-4 px-4 py-3.5 transition-all hover:shadow-md hover:border-gray-200 group"
    >
      {/* Type icon */}
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gray-50 text-gray-400 group-hover:bg-brand-50 group-hover:text-brand-500 transition-colors">
        {typeIcons[scan.scan_type] ?? <File size={16} />}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium text-gray-900 truncate">{scan.target}</p>
          <VerdictBadge verdict={scan.verdict} size="sm" />
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="flex items-center gap-1 text-xs text-gray-400">
            {statusIcons[scan.status]}
            {scan.status === "completed" ? "Done" : scan.status === "failed" ? "Failed" : scan.status === "running" ? "Running" : "Queued"}
          </span>
          {scan.threat_score !== null && scan.status === "completed" && (
            <span className="text-xs text-gray-400">
              Score: <span className="font-medium text-gray-600">{scan.threat_score}</span>/100
            </span>
          )}
          {scan.file_hash_sha256 && (
            <span className="hidden sm:inline text-xs text-gray-400 font-mono">
              {shortHash(scan.file_hash_sha256, 8)}
            </span>
          )}
        </div>
      </div>

      {/* Time */}
      <div className="hidden sm:block text-right shrink-0">
        <p className="text-xs text-gray-400">{timeAgo(scan.created_at)}</p>
      </div>
    </Link>
  );
}
