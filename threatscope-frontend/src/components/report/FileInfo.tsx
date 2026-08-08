"use client";

import { useState } from "react";
import { FileText, ChevronDown, Lock, ShieldAlert, ExternalLink } from "lucide-react";
import type { FileInfo, VTResult, SSLResult } from "@/types";
import { cn, formatBytes } from "@/lib/utils";
import { CopyButton } from "@/components/ui/CopyButton";

/* ── FileInfo panel ──────────────────────── */

export function FileInfoPanel({ data }: { data: FileInfo }) {
  const [open, setOpen] = useState(true);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <FileText size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">File Information</span>
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-2">
          <Row label="Size" value={formatBytes(data.size_bytes)} />
          <Row label="MD5" value={data.md5} mono copy />
          <Row label="SHA-256" value={data.sha256} mono copy />
        </div>
      )}
    </div>
  );
}

/* ── VT panel ────────────────────────────── */

export function VTPanel({ data }: { data: VTResult }) {
  const malicious = data.vt_malicious_count ?? 0;
  const total = data.vt_total_engines ?? 0;
  const pct = total > 0 ? (malicious / total) * 100 : 0;
  const [open, setOpen] = useState(malicious > 0 || !data.vt_available);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <ShieldAlert size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">VirusTotal</span>
        {!data.vt_available ? (
          <span className="text-xs text-amber-600 mr-2">Temporarily unavailable</span>
        ) : !data.vt_found ? (
          <span className="text-xs text-gray-500 mr-2">Not in VT</span>
        ) : (
          <span className={cn("text-xs font-semibold mr-2", malicious > 0 ? "text-red-600" : "text-emerald-600")}>
            {malicious}/{total} detections
          </span>
        )}
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-3">
          {!data.vt_available ? (
            <div className="bg-amber-50 border border-amber-100 rounded-md p-3">
              <p className="text-sm text-amber-800 font-medium">VirusTotal lookup temporarily unavailable.</p>
              {data.error && <p className="text-xs text-amber-700 mt-1">{data.error}</p>}
            </div>
          ) : !data.vt_found ? (
            <p className="text-sm text-gray-500">This sample has not been seen by VirusTotal.</p>
          ) : (
            <>
              <div className="flex items-center gap-4">
                <div className="flex-1 h-2 rounded-full bg-gray-100 overflow-hidden">
                  <div className={cn("h-full rounded-full transition-all", pct > 30 ? "bg-red-500" : pct > 10 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${pct}%` }} />
                </div>
                <span className="text-sm font-semibold tabular-nums text-gray-700">{malicious}/{total}</span>
              </div>
              <div className="flex items-center justify-between mt-3">
                {data.vt_popular_threat_name ? (
                  <p className="text-sm"><span className="text-gray-500">Threat name:</span> <span className="font-medium text-red-600">{data.vt_popular_threat_name}</span></p>
                ) : <span />}
                {data.vt_report_url && (
                  <a
                    href={data.vt_report_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center text-xs font-medium text-blue-600 hover:text-blue-800"
                  >
                    View on VirusTotal
                    <ExternalLink size={12} className="ml-1" />
                  </a>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ── SSL panel ───────────────────────────── */

export function SSLPanel({ data }: { data: SSLResult }) {
  const [open, setOpen] = useState(!data.is_valid);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Lock size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">SSL Certificate</span>
        {!data.ssl_available ? (
          <span className="text-xs text-gray-400 mr-2">N/A</span>
        ) : data.is_valid ? (
          <span className="text-xs text-emerald-600 font-medium mr-2">Valid</span>
        ) : (
          <span className="text-xs text-red-600 font-medium mr-2">Issues</span>
        )}
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-3">
          {!data.ssl_available ? (
            <p className="text-sm text-gray-500">SSL inspection not available. {data.error ?? ""}</p>
          ) : (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <Cell label="Issued to" value={data.issued_to} />
                <Cell label="Issued by" value={data.issued_by} />
                <Cell label="Issuer org" value={data.issuer_org} />
                <Cell label="Valid from" value={data.valid_from} />
                <Cell label="Valid until" value={data.valid_until} />
                <Cell label="Days left" value={data.days_until_expiry?.toString()} warn={(data.days_until_expiry ?? 999) <= 7} />
                <Cell label="TLS version" value={data.tls_version} />
                <Cell label="Self-signed" value={data.is_self_signed ? "Yes" : "No"} warn={data.is_self_signed} />
                <Cell label="Expired" value={data.is_expired ? "Yes" : "No"} warn={data.is_expired} />
              </div>
              {data.ssl_notes && data.ssl_notes.length > 0 && (
                <div className="space-y-1">
                  {data.ssl_notes.map((note, i) => (
                    <p key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                      <span className="mt-1 h-1 w-1 rounded-full bg-gray-400 shrink-0" />{note}
                    </p>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Helpers ──────────────────────────────── */

function Row({ label, value, mono, copy }: { label: string; value: string; mono?: boolean; copy?: boolean }) {
  return (
    <div className="flex items-center gap-2 group">
      <span className="text-xs text-gray-400 w-16 shrink-0">{label}</span>
      <span className={cn("text-sm text-gray-700 truncate", mono && "font-mono text-xs")}>{value}</span>
      {copy && <CopyButton text={value} className="opacity-0 group-hover:opacity-100 transition-opacity" />}
    </div>
  );
}

function Cell({ label, value, warn }: { label: string; value?: string; warn?: boolean }) {
  return (
    <div>
      <p className="text-[11px] text-gray-400 uppercase tracking-wider">{label}</p>
      <p className={cn("text-sm font-medium mt-0.5 truncate", warn ? "text-red-600" : "text-gray-900")}>{value ?? "—"}</p>
    </div>
  );
}
