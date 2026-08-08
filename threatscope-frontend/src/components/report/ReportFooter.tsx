import React from "react";
import { Flag } from "lucide-react";
import type { ScanResult } from "@/types";
import { cn } from "@/lib/utils";

interface ReportFooterProps {
  scan: ScanResult;
  className?: string;
}

export function ReportFooter({ scan, className }: ReportFooterProps) {
  const timestamp = new Date(scan.created_at).toLocaleString();
  const mailtoLink = `mailto:feedback@threatscope.ai?subject=Flag%20${scan.job_id}`;

  return (
    <div className={cn("mt-8 border-t border-gray-200 pt-6 pb-12 flex flex-col sm:flex-row items-center justify-between text-sm text-gray-500", className)}>
      <div className="mb-4 sm:mb-0">
        Report generated at {timestamp} &middot; Job ID {scan.job_id}
      </div>
      <a
        href={mailtoLink}
        className="inline-flex items-center text-gray-500 hover:text-gray-900 transition-colors"
      >
        <Flag className="w-4 h-4 mr-1.5" />
        Flag this result
      </a>
    </div>
  );
}
