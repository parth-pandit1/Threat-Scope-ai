"use client";

import type { SignalScore } from "@/types";
import { humanize } from "@/lib/utils";

interface Props {
  breakdown: Record<string, SignalScore>;
}

export function ScoreBreakdown({ breakdown }: Props) {
  const entries = Object.entries(breakdown).sort(([, a], [, b]) => b.score - a.score);
  if (entries.length === 0) return null;

  return (
    <div className="space-y-3">
      {entries.map(([key, signal]) => {
        const pct = signal.max > 0 ? (signal.score / signal.max) * 100 : 0;
        const barColor =
          pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-amber-500" : pct > 0 ? "bg-blue-500" : "bg-gray-200";

        return (
          <div key={key}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-gray-700">{humanize(key)}</span>
              <span className="text-xs tabular-nums text-gray-500">{signal.score} / {signal.max}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-gray-100 overflow-hidden">
              <div className={`h-full rounded-full transition-all duration-500 ease-out ${barColor}`} style={{ width: `${pct}%` }} />
            </div>
            <p className="text-xs text-gray-400 mt-0.5">{signal.detail}</p>
          </div>
        );
      })}
    </div>
  );
}
