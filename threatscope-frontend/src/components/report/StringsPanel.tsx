"use client";

import { useState } from "react";
import { Type, Activity, ChevronDown } from "lucide-react";
import type { StringsResult, EntropyResult } from "@/types";
import { cn, humanize } from "@/lib/utils";

/* ── Strings panel ───────────────────────── */

export function StringsPanel({ data }: { data: StringsResult }) {
  const [open, setOpen] = useState(data.suspicious_count > 0);
  const categories = Object.entries(data.suspicious_strings ?? {}).filter(([, arr]) => arr.length > 0);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Type size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">String Analysis</span>
        <span className="text-xs text-gray-500 font-medium mr-2">{data.suspicious_count} suspicious / {data.total_count} total</span>
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4">
          {categories.length === 0 ? (
            <p className="text-sm text-gray-500">No suspicious strings detected.</p>
          ) : (
            <div className="space-y-4">
              {categories.map(([category, strings]) => (
                <div key={category}>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">{humanize(category)} ({strings.length})</p>
                  <div className="space-y-1">
                    {strings.slice(0, 8).map((s, i) => (
                      <code key={i} className="block text-xs text-gray-700 bg-gray-50 rounded px-2 py-1 truncate">{s}</code>
                    ))}
                    {strings.length > 8 && <p className="text-xs text-gray-400">+{strings.length - 8} more</p>}
                  </div>
                </div>
              ))}
              {data.decoded_base64 && data.decoded_base64.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-amber-600 uppercase tracking-wider mb-1.5">Decoded Base64</p>
                  {data.decoded_base64.map((s, i) => (
                    <code key={i} className="block text-xs text-amber-800 bg-amber-50 rounded px-2 py-1 mb-1">{s}</code>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Entropy panel ───────────────────────── */

const labelColor: Record<string, string> = {
  normal: "text-emerald-600",
  elevated: "text-blue-600",
  high: "text-amber-600",
  very_high: "text-red-600",
};

export function EntropyPanel({ data }: { data: EntropyResult }) {
  const [open, setOpen] = useState(data.entropy_label !== "normal");

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Activity size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">Entropy Analysis</span>
        <span className={cn("text-xs font-semibold mr-2", labelColor[data.entropy_label] ?? "text-gray-500")}>
          {data.value?.toFixed(2)} — {humanize(data.entropy_label)}
        </span>
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-4">
          <p className="text-sm text-gray-600">{data.entropy_note}</p>

          {data.section_entropy && data.section_entropy.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Section Entropy</p>
              <div className="space-y-2">
                {data.section_entropy.map((s, i) => {
                  const pct = (s.entropy / 8) * 100;
                  const barColor = s.entropy > 7 ? "bg-red-500" : s.entropy > 6.5 ? "bg-amber-500" : "bg-emerald-500";
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <code className="text-xs text-gray-500 w-20 truncate">{s.name || "(empty)"}</code>
                      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs tabular-nums text-gray-500 w-10 text-right">{s.entropy.toFixed(1)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
