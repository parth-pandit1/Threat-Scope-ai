"use client";

import { useState } from "react";
import { Cpu, ChevronDown, AlertTriangle } from "lucide-react";
import type { PEAnalysis } from "@/types";
import { cn } from "@/lib/utils";

interface Props { data: PEAnalysis }

export function PEAnalysisPanel({ data }: Props) {
  const [open, setOpen] = useState(data.is_pe);
  if (!data.is_pe) return null;

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Cpu size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">PE Analysis</span>
        <span className="text-xs text-gray-500 font-medium mr-2">Score: {data.pe_score}/30</span>
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-4">
          {/* Info grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <Cell label="Machine" value={data.machine_type} />
            <Cell label="Subsystem" value={data.subsystem} />
            <Cell label="Compiled" value={data.compile_timestamp ?? "Unknown"} warn={data.is_timestamp_suspicious} />
            <Cell label="DLL" value={data.is_dll ? "Yes" : "No"} />
            <Cell label="Driver" value={data.is_driver ? "Yes" : "No"} />
            <Cell label="Overlay" value={data.overlay_size ? `${data.overlay_size} bytes` : "None"} />
          </div>

          {/* Suspicious imports */}
          {data.suspicious_imports && data.suspicious_imports.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-red-600 uppercase tracking-wider mb-2 flex items-center gap-1">
                <AlertTriangle size={12} /> Suspicious Imports ({data.suspicious_imports.length})
              </p>
              <div className="flex flex-wrap gap-1.5">
                {data.suspicious_imports.map((imp) => (
                  <code key={imp} className="rounded bg-red-50 border border-red-100 px-2 py-0.5 text-xs text-red-700">{imp}</code>
                ))}
              </div>
            </div>
          )}

          {/* Sections table */}
          {data.sections && data.sections.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Sections ({data.sections.length})</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-gray-400 border-b border-gray-100">
                      <th className="py-1.5 pr-3 font-medium">Name</th>
                      <th className="py-1.5 pr-3 font-medium">Flags</th>
                      <th className="py-1.5 pr-3 font-medium">Entropy</th>
                      <th className="py-1.5 font-medium">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sections.map((s, i) => (
                      <tr key={i} className="border-b border-gray-50">
                        <td className="py-1.5 pr-3 font-mono">{s.name || "(empty)"}</td>
                        <td className="py-1.5 pr-3 font-mono">{s.flags}</td>
                        <td className={cn("py-1.5 pr-3 tabular-nums", s.entropy > 7 && "text-red-600 font-medium")}>{s.entropy.toFixed(2)}</td>
                        <td className="py-1.5 tabular-nums">{s.raw_size.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
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
