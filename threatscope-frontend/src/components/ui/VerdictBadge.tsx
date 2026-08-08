"use client";

import type { Verdict } from "@/types";
import { verdictClasses } from "@/lib/utils";

interface Props {
  verdict: Verdict | null;
  size?: "sm" | "md" | "lg";
}

export function VerdictBadge({ verdict, size = "md" }: Props) {
  if (!verdict) return null;
  const vc = verdictClasses(verdict);

  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-[10px]",
    md: "px-2 py-0.5 text-xs",
    lg: "px-3.5 py-1 text-sm",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ${vc.pill} ${sizeClasses[size]}`}
    >
      <span
        className={`rounded-full ${vc.dot} ${
          size === "lg" ? "h-2 w-2" : "h-1.5 w-1.5"
        }`}
      />
      {vc.label}
    </span>
  );
}
