"use client";

import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import type { ScanStatus } from "@/types";
import { cn } from "@/lib/utils";

interface Props {
  status: ScanStatus;
  target: string;
}

export function ScanProgress({ status, target }: Props) {
  const steps: { key: ScanStatus; label: string }[] = [
    { key: "queued", label: "Queued" },
    { key: "running", label: "Analysing" },
    { key: "completed", label: "Complete" },
  ];

  const isFailed = status === "failed";
  const currentIndex = steps.findIndex((s) => s.key === status);

  return (
    <div className="card p-6 animate-fade-in">
      <div className="flex items-center gap-3 mb-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
          {status === "completed" ? (
            <CheckCircle2 size={20} />
          ) : isFailed ? (
            <XCircle size={20} className="text-red-500" />
          ) : (
            <Loader2 size={20} className="animate-spin" />
          )}
        </div>
        <div>
          <p className="text-sm font-semibold text-gray-900">
            {isFailed ? "Scan failed" : status === "completed" ? "Scan complete" : "Scanning…"}
          </p>
          <p className="text-xs text-gray-500 truncate max-w-[300px]">{target}</p>
        </div>
      </div>

      {/* Progress steps */}
      {!isFailed && (
        <div className="flex items-center gap-2">
          {steps.map((step, i) => {
            const isActive = i === currentIndex;
            const isDone = i < currentIndex || status === "completed";

            return (
              <div key={step.key} className="flex items-center gap-2 flex-1">
                <div className="flex items-center gap-2 flex-1">
                  <div
                    className={cn(
                      "flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium shrink-0 transition-colors",
                      isDone
                        ? "bg-brand-600 text-white"
                        : isActive
                          ? "bg-brand-100 text-brand-700 ring-2 ring-brand-200"
                          : "bg-gray-100 text-gray-400",
                    )}
                  >
                    {isDone ? "✓" : i + 1}
                  </div>
                  <span
                    className={cn(
                      "text-xs font-medium hidden sm:inline",
                      isDone || isActive ? "text-gray-900" : "text-gray-400",
                    )}
                  >
                    {step.label}
                  </span>
                </div>
                {i < steps.length - 1 && (
                  <div
                    className={cn(
                      "h-0.5 flex-1 rounded-full transition-colors",
                      isDone ? "bg-brand-600" : "bg-gray-200",
                    )}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      {isFailed && (
        <div className="rounded-lg bg-red-50 border border-red-100 px-4 py-3 text-sm text-red-700">
          The scan could not be completed. This may be a temporary issue — try submitting again.
        </div>
      )}
    </div>
  );
}
