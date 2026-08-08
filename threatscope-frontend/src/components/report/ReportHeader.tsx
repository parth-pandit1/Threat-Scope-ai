"use client";

import { File, Globe, Hash, Info, AlertTriangle, Check } from "lucide-react";
import type { ScanResult } from "@/types";
import { formatDate, formatBytes } from "@/lib/utils";
import { CopyButton } from "@/components/ui/CopyButton";
import { VerdictBadge } from "@/components/ui/VerdictBadge";
import { ThreatGauge } from "@/components/report/ThreatGauge";

interface Props {
  scan: ScanResult;
}

export function ReportHeader({ scan }: Props) {
  const r = scan.result;

  return (
    <div className="card p-6 animate-slide-up">
      <div className="flex flex-col sm:flex-row sm:items-center gap-6">
        {/* Left: meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600 shrink-0">
              {scan.scan_type === "file" ? <File size={20} /> : <Globe size={20} />}
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-bold text-gray-900 truncate">{scan.target}</h1>
              <p className="text-xs text-gray-400">
                {scan.scan_type === "file" ? "File scan" : "URL scan"} · {formatDate(scan.created_at)}
              </p>
            </div>
          </div>

          {/* Hashes */}
          {scan.file_hash_sha256 && (
            <div className="space-y-1.5">
              <HashRow label="SHA-256" hash={scan.file_hash_sha256} />
              {scan.file_hash_md5 && <HashRow label="MD5" hash={scan.file_hash_md5} />}
              {r?.file_info?.size_bytes != null && (
                <p className="text-xs text-gray-400">Size: {formatBytes(r.file_info.size_bytes)}</p>
              )}
            </div>
          )}
        </div>

        {/* Right: gauge + verdict */}
        {scan.status === "completed" && scan.threat_score !== null && (
          <div className="flex flex-col items-center gap-2 shrink-0">
            <ThreatGauge score={scan.threat_score} verdict={scan.verdict} />
            <VerdictBadge verdict={scan.verdict} size="lg" />
          </div>
        )}
      </div>

      {/* Reasons */}
      {scan.status === "completed" && r?.threat_score_breakdown && (
        <div className="mt-6 pt-5 border-t border-gray-100">
          <p className="text-sm font-semibold text-gray-900 mb-3">Key Findings</p>
          {r.threat_score_breakdown.reasons.length === 0 ? (
            <p className="text-sm text-gray-500 flex items-center gap-2">
              <Check size={14} className="text-emerald-500" />
              No significant threat indicators detected
            </p>
          ) : (
            <div className="space-y-1.5">
              {r.threat_score_breakdown.reasons.map((reason, i) => (
                <p key={i} className="text-sm text-gray-600 flex items-start gap-2">
                  <Info size={13} className="text-gray-400 shrink-0 mt-0.5" />
                  {reason}
                </p>
              ))}
            </div>
          )}
          {r.threat_score_breakdown.top_threat && (
            <div className="mt-3 flex items-center gap-2 bg-red-50 border border-red-100 rounded-lg px-3 py-2">
              <AlertTriangle size={14} className="text-red-500 shrink-0" />
              <span className="text-sm text-red-700">
                Top threat: <strong>{r.threat_score_breakdown.top_threat}</strong>
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function HashRow({ label, hash }: { label: string; hash: string }) {
  return (
    <div className="flex items-center gap-2 group">
      <Hash size={12} className="text-gray-300 shrink-0" />
      <span className="text-[11px] text-gray-400 w-12 shrink-0">{label}</span>
      <code className="text-xs text-gray-600 font-mono truncate">{hash}</code>
      <CopyButton text={hash} className="opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}
