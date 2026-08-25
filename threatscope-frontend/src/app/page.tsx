"use client";

/* ───────────────────────────────────────────
   Landing page — scan form front and center.
   No auth. Anyone can submit.
   ─────────────────────────────────────────── */

import { Shield, Zap, Eye, Brain } from "lucide-react";
import { ScanForm } from "@/components/scan/ScanForm";
import { useStats } from "@/hooks/useStats";
import { SkeletonLine } from "@/components/ui/Skeleton";

export default function HomePage() {
  const { stats, loading: statsLoading } = useStats();

  return (
    <div className="page-container py-10 sm:py-16 space-y-16">
      {/* Hero */}
      <div className="text-center max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-2 rounded-full bg-brand-50 border border-brand-100 px-3 py-1 text-xs font-medium text-brand-700 mb-6">
          <span className="h-1.5 w-1.5 rounded-full bg-brand-500 animate-pulse-dot" />
          Open Threat Intelligence Platform
        </div>
        
        <h1 className="text-3xl sm:text-4xl font-bold text-gray-900 tracking-tight">
          Analyse threats with{" "}
          <span className="text-brand-600">AI-powered</span> intelligence
        </h1>
        <p className="mt-4 text-base text-gray-500 leading-relaxed max-w-lg mx-auto">
          Upload files, submit URLs, or check IP addresses. Get deep analysis with
          YARA scanning, PE parsing, IOC extraction, and AI threat explanations.
        </p>
      </div>

      {/* Stat Strip */}
      <div className="flex justify-center -mt-6 mb-2">
        {statsLoading ? (
          <SkeletonLine className="w-64 h-5" />
        ) : stats ? (
          <p className="text-sm font-medium text-gray-500">
            <span className="text-gray-900">{stats.total_scans.toLocaleString()}</span> scans completed &middot;{" "}
            <span className="text-brand-600">{stats.malicious_scans.toLocaleString()}</span> threats detected &middot;{" "}
            Since {stats.start_date.split("T")[0]}
          </p>
        ) : null}
      </div>

      {/* Scan Form — always visible, no auth gate */}
      <div className="max-w-2xl mx-auto">
        <ScanForm />
      </div>

      {/* Features */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl mx-auto">
        {features.map((f) => (
          <div key={f.title} className="card p-5 group hover:border-gray-200 transition-colors">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-50 text-brand-600 mb-3 group-hover:scale-105 transition-transform">
              {f.icon}
            </div>
            <p className="text-sm font-semibold text-gray-900">{f.title}</p>
            <p className="text-xs text-gray-500 mt-1 leading-relaxed">{f.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

const features = [
  {
    icon: <Shield size={18} />,
    title: "YARA Scanning",
    desc: "Custom + community rules matched against every file submission.",
  },
  {
    icon: <Zap size={18} />,
    title: "PE Analysis",
    desc: "Header parsing, suspicious imports, section entropy, overlay detection.",
  },
  {
    icon: <Eye size={18} />,
    title: "IOC Extraction",
    desc: "IPs, domains, hashes, registry keys, CVEs, and MITRE techniques.",
  },
  {
    icon: <Brain size={18} />,
    title: "AI Explanation",
    desc: "Local LLM generates plain-English threat assessments with remediation steps.",
  },
];
