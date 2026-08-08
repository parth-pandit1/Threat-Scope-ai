"use client";

/* ───────────────────────────────────────────
   Landing page — scan form front and center.
   No auth. Anyone can submit.
   ─────────────────────────────────────────── */

import { Shield, Zap, Eye, Brain, Loader2 } from "lucide-react";
import { ScanForm } from "@/components/scan/ScanForm";
import { useStats } from "@/hooks/useStats";
import { SkeletonLine } from "@/components/ui/Skeleton";
import { useAuth } from "@/context/AuthContext";
import Link from "next/link";

export default function HomePage() {
  const { stats, loading: statsLoading } = useStats();
  const { user, loading: authLoading } = useAuth();

  if (authLoading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="animate-spin text-brand-600" size={32} />
          <p className="text-sm font-medium text-gray-500">Securing environment...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container py-10 sm:py-16 space-y-16">
      {/* Hero */}
      <div className="text-center max-w-2xl mx-auto">
        {user ? (
          <div className="inline-flex items-center gap-2 rounded-full bg-brand-50 border border-brand-100 px-3 py-1 text-xs font-medium text-brand-700 mb-6">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-500 animate-pulse-dot" />
            Authenticated Session &middot; Tier: <span className="uppercase font-bold">{user.tier}</span>
          </div>
        ) : (
          <div className="inline-flex items-center gap-2 rounded-full bg-brand-50 border border-brand-100 px-3 py-1 text-xs font-medium text-brand-700 mb-6">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
            Secure Threat Platform &middot; Authentication Required
          </div>
        )}
        
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

      {/* Main Content Area */}
      <div className="max-w-2xl mx-auto">
        {user ? (
          <ScanForm />
        ) : (
          <div className="card p-8 bg-white border border-gray-200 shadow-sm rounded-lg text-center space-y-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-brand-50 text-brand-600 mx-auto">
              <Shield size={24} />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-bold text-gray-900">Unlock Deep Threat Analysis</h3>
              <p className="text-sm text-gray-500 max-w-md mx-auto leading-relaxed">
                Sign in or create a free account to scan executable files, domains, and IP addresses. 
                Get direct access to sandboxed static scanning and MITRE mapping.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 justify-center pt-2">
              <Link href="/register" className="btn-primary text-sm px-5 py-2.5 shadow-sm">
                Get Started for Free
              </Link>
              <Link
                href="/login"
                className="flex items-center justify-center px-5 py-2.5 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 border border-gray-200 transition-colors"
              >
                Sign In
              </Link>
            </div>
          </div>
        )}
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
