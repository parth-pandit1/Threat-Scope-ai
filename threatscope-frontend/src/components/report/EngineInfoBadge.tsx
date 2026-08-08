import React from "react";
import { cn } from "@/lib/utils";

interface EngineInfoBadgeProps {
  label: string;
  value: string | number;
  date?: string;
  className?: string;
}

export function EngineInfoBadge({ label, value, date, className }: EngineInfoBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600",
        className
      )}
    >
      {label}: {date ? `${date} · ` : ""}{value}
    </span>
  );
}
