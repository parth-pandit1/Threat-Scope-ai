"use client";

import { useState, useEffect } from "react";
import { Shield, ChevronDown, AlertTriangle } from "lucide-react";
import type { YARAResult, HealthStatus } from "@/types";
import { cn } from "@/lib/utils";
import { EngineInfoBadge } from "./EngineInfoBadge";
import { api } from "@/lib/api";

interface Props { data: YARAResult }

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-700 border-red-200",
  high: "bg-red-50 text-red-600 border-red-100",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  low: "bg-blue-50 text-blue-700 border-blue-200",
  info: "bg-gray-50 text-gray-600 border-gray-200",
};

export function YaraMatches({ data }: Props) {
  const [open, setOpen] = useState(data.match_count > 0);
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
  }, []);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Shield size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">
          YARA Rules
          {health?.yara && (
            <EngineInfoBadge 
              label="YARA ruleset" 
              date={health.yara.last_updated.split("T")[0]} 
              value={`${health.yara.rule_count.toLocaleString()} rules`}
              className="ml-3 hidden sm:inline-flex"
            />
          )}
        </span>
        {data.match_count > 0 ? (
          <span className="text-xs font-semibold text-red-600 mr-2">{data.match_count} match{data.match_count > 1 ? "es" : ""}</span>
        ) : (
          <span className="text-xs text-emerald-600 font-medium mr-2">No matches</span>
        )}
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4">
          {!data.yara_available ? (
            <p className="text-sm text-gray-500">YARA engine not available.</p>
          ) : data.matches.length === 0 ? (
            <p className="text-sm text-gray-500">No YARA rules matched this sample.</p>
          ) : (
            <div className="space-y-3">
              {data.malware_families.length > 0 && (
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle size={14} className="text-red-500" />
                  <span className="text-sm font-medium text-red-700">
                    Families: {data.malware_families.join(", ")}
                  </span>
                </div>
              )}
              {data.matches.map((m, i) => (
                <div key={i} className="rounded-lg border border-gray-100 p-3">
                  <div className="flex flex-wrap items-center gap-2 mb-1.5">
                    <span className="text-sm font-semibold text-gray-900">{m.rule}</span>
                    <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-medium border", severityColors[m.severity] ?? severityColors.info)}>
                      {m.severity}
                    </span>
                    {m.source_repo && (
                      <span className="rounded-full px-2 py-0.5 text-[10px] font-medium border bg-gray-50 border-gray-200 text-gray-600">
                        {m.source_repo}
                      </span>
                    )}
                  </div>
                  {m.meta.description && <p className="text-xs text-gray-500 mb-2">{m.meta.description}</p>}
                  {m.strings_matched.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {m.strings_matched.slice(0, 5).map((s, j) => (
                        <code key={j} className="text-[11px] bg-gray-50 text-gray-600 rounded px-1.5 py-0.5">{s}</code>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
