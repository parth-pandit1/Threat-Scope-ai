"use client";

/* ───────────────────────────────────────────
   Scan Result Page — /scan/[id]
   Public. No auth. Polls until done.
   ─────────────────────────────────────────── */

import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, AlertTriangle } from "lucide-react";
import { useScan } from "@/hooks/useScan";
import { SkeletonReport } from "@/components/ui/Skeleton";
import { ScanProgress } from "@/components/scan/ScanProgress";
import { ReportHeader } from "@/components/report/ReportHeader";
import { ScoreBreakdown } from "@/components/report/ScoreBreakdown";
import { EntropyPanel, StringsPanel } from "@/components/report/StringsPanel";
import { PEAnalysisPanel } from "@/components/report/PEAnalysis";
import { YaraMatches } from "@/components/report/YaraMatches";
import { IOCTable } from "@/components/report/IOCTable";
import { FileInfoPanel, VTPanel, SSLPanel } from "@/components/report/FileInfo";
import { ScreenshotPanel } from "@/components/report/ScreenshotPanel";
import { AIExplanationPanel } from "@/components/report/AIExplanation";
import { ReportFooter } from "@/components/report/ReportFooter";

export default function ScanResultPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { scan, loading, error } = useScan(id);

  /* Loading */
  if (loading) {
    return (
      <div className="page-container py-8 sm:py-12">
        <SkeletonReport />
      </div>
    );
  }

  /* Error */
  if (error || !scan) {
    return (
      <div className="page-container py-20 flex flex-col items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-50">
          <AlertTriangle className="text-red-500" size={20} />
        </div>
        <p className="text-sm font-medium text-gray-900">Scan not found</p>
        <p className="text-xs text-gray-500">{error ?? "Unknown error"}</p>
        <button onClick={() => router.push("/")} className="btn-secondary mt-2">Back to home</button>
      </div>
    );
  }

  const r = scan.result;
  const isRunning = scan.status === "queued" || scan.status === "running";

  return (
    <div className="page-container py-8 sm:py-12 space-y-6">
      {/* Back */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700 transition-colors"
      >
        <ArrowLeft size={14} /> Back
      </button>

      {/* Progress (queued/running) */}
      {isRunning && <ScanProgress status={scan.status} target={scan.target} />}

      {/* Header (always shown once data exists) */}
      <ReportHeader scan={scan} />

      {/* Full results — only when completed */}
      {scan.status === "completed" && r && (
        <>
          {/* Score breakdown */}
          {r.threat_score_breakdown && (
            <div className="card p-5 animate-slide-up">
              <h2 className="section-title mb-4">Score Breakdown</h2>
              <ScoreBreakdown breakdown={r.threat_score_breakdown.breakdown} />
            </div>
          )}

          {/* Analysis modules */}
          <div className="space-y-3">
            {/* File-specific */}
            {r.file_info && <FileInfoPanel data={r.file_info} />}
            {r.entropy && <EntropyPanel data={r.entropy} />}
            {r.pe_analysis && r.pe_analysis.is_pe && <PEAnalysisPanel data={r.pe_analysis} />}
            {r.strings && <StringsPanel data={r.strings} />}
            {r.yara && <YaraMatches data={r.yara} />}

            {/* URL-specific */}
            {r.ssl && <SSLPanel data={r.ssl} />}
            {(r.screenshot || r.page_intel) && (
              <ScreenshotPanel screenshot={r.screenshot} pageIntel={r.page_intel} />
            )}

            {/* Common */}
            {r.iocs && r.iocs.total_ioc_count > 0 && <IOCTable data={r.iocs} />}
            {r.virustotal && <VTPanel data={r.virustotal} />}
            {r.ai_explanation && <AIExplanationPanel data={r.ai_explanation} />}
          </div>
          
          <ReportFooter scan={scan} />
        </>
      )}
    </div>
  );
}
