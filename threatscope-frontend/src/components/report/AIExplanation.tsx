"use client";

import { useState } from "react";
import { Sparkles, ChevronDown, ChevronRight } from "lucide-react";
import type { AIExplanation } from "@/types";
import { cn } from "@/lib/utils";

interface Props { data: AIExplanation }

export function AIExplanationPanel({ data }: Props) {
  const [open, setOpen] = useState(data.ai_available === true);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Sparkles size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">AI Analysis</span>
        {data.ai_available ? (
          <span className="text-xs text-brand-600 font-medium mr-2">
            {data.model_used ?? "LLM"} · {data.confidence ?? "—"} confidence
          </span>
        ) : (
          <span className="text-xs text-gray-400 mr-2">Unavailable</span>
        )}
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-5">
          {!data.ai_available ? (
            <p className="text-sm text-gray-500">AI explanation not available. {data.error ?? ""}</p>
          ) : (
            <>
              {data.explanation && (
                <div className="text-sm text-gray-700 whitespace-pre-wrap leading-relaxed">{data.explanation}</div>
              )}

              {data.mitre_techniques && data.mitre_techniques.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">MITRE ATT&CK Techniques</p>
                  <div className="space-y-1.5">
                    {data.mitre_techniques.map((t, i) => (
                      <div key={i} className="flex items-center gap-2 rounded-lg bg-gray-50 px-3 py-2">
                        <code className="text-xs font-semibold text-brand-600 shrink-0">{t.id}</code>
                        <span className="text-xs text-gray-700 flex-1">{t.name}</span>
                        <span className="text-[11px] text-gray-400 shrink-0">{t.tactic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {data.recommended_actions && data.recommended_actions.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Recommended Actions</p>
                  <div className="space-y-2">
                    {data.recommended_actions.map((action, i) => (
                      <div key={i} className="flex items-start gap-2 rounded-lg border border-gray-100 px-3 py-2.5">
                        <ChevronRight size={14} className="text-brand-500 shrink-0 mt-0.5" />
                        <span className="text-sm text-gray-700">{action}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
