/* ───────────────────────────────────────────
   ThreatScope AI — UI utility helpers
   ─────────────────────────────────────────── */

import type { Verdict } from "@/types";

/** Merge class names, filtering falsy values. */
export function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

/** Format a byte count into a human-readable string. */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/** Format an ISO timestamp to a readable date/time. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Relative time (e.g., "3 min ago"). */
export function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/** Truncate a hash for display. */
export function shortHash(hash: string | null | undefined, len = 12): string {
  if (!hash) return "—";
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}…`;
}

/** Get the color hex value for a verdict (SVG usage). */
export function verdictColor(verdict: Verdict | null): string {
  const map: Record<Verdict, string> = {
    clean: "#10b981",
    low_risk: "#3b82f6",
    suspicious: "#f59e0b",
    malicious: "#ef4444",
  };
  return verdict ? map[verdict] : "#9ca3af";
}

/** Get Tailwind classes for a verdict. */
export function verdictClasses(verdict: Verdict | null) {
  const map: Record<Verdict, { pill: string; dot: string; label: string }> = {
    clean: {
      pill: "bg-emerald-50 text-emerald-700 border border-emerald-200",
      dot: "bg-emerald-500",
      label: "Clean",
    },
    low_risk: {
      pill: "bg-blue-50 text-blue-700 border border-blue-200",
      dot: "bg-blue-500",
      label: "Low Risk",
    },
    suspicious: {
      pill: "bg-amber-50 text-amber-700 border border-amber-200",
      dot: "bg-amber-500",
      label: "Suspicious",
    },
    malicious: {
      pill: "bg-red-50 text-red-700 border border-red-200",
      dot: "bg-red-500",
      label: "Malicious",
    },
  };
  return verdict
    ? map[verdict]
    : { pill: "bg-gray-50 text-gray-500 border border-gray-200", dot: "bg-gray-400", label: "Pending" };
}

/** Capitalize first letter, replace underscores. */
export function humanize(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
