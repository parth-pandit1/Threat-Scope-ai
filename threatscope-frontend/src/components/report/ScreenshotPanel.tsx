"use client";

import { useState } from "react";
import { Camera, ChevronDown, ExternalLink } from "lucide-react";
import type { ScreenshotResult, PageIntel } from "@/types";
import { cn } from "@/lib/utils";

interface Props {
  screenshot?: ScreenshotResult;
  pageIntel?: PageIntel;
}

export function ScreenshotPanel({ screenshot, pageIntel }: Props) {
  const hasData = screenshot?.screenshot_available || pageIntel?.page_intel_available;
  const [open, setOpen] = useState(!!hasData);

  const hasFindings = (pageIntel?.hidden_iframes?.length ?? 0) > 0 ||
    pageIntel?.has_password_field || pageIntel?.has_login_form;

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Camera size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">Screenshot &amp; Page Intel</span>
        {hasFindings ? (
          <span className="text-xs text-amber-600 font-medium mr-2">⚠ Findings</span>
        ) : hasData ? (
          <span className="text-xs text-emerald-600 font-medium mr-2">Captured</span>
        ) : (
          <span className="text-xs text-gray-400 mr-2">N/A</span>
        )}
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4 space-y-4">
          {/* Screenshot metadata */}
          {screenshot && screenshot.screenshot_available && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <Cell label="Page title" value={screenshot.page_title} />
              <Cell label="Load time" value={screenshot.page_load_time_ms ? `${screenshot.page_load_time_ms}ms` : undefined} />
              <Cell label="Redirects" value={screenshot.redirect_count?.toString()} />
              {screenshot.final_url && (
                <div className="col-span-2 sm:col-span-3">
                  <p className="text-[11px] text-gray-400 uppercase tracking-wider">Final URL</p>
                  <a href={screenshot.final_url} target="_blank" rel="noopener noreferrer"
                    className="text-xs text-brand-600 hover:underline flex items-center gap-1 mt-0.5 truncate">
                    {screenshot.final_url} <ExternalLink size={10} />
                  </a>
                </div>
              )}
            </div>
          )}

          {screenshot?.screenshot_url && (
            <div className="overflow-hidden rounded-lg border border-gray-100 bg-gray-50 flex items-center justify-center p-1">
              <img
                src={screenshot.screenshot_url}
                alt="Website screenshot"
                className="w-full max-h-[350px] object-contain cursor-zoom-in rounded hover:opacity-95 transition-opacity"
                onClick={() => window.open(screenshot.screenshot_url!, "_blank")}
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                }}
              />
            </div>
          )}

          {screenshot?.redirect_chain && screenshot.redirect_chain.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Redirect Chain</p>
              {screenshot.redirect_chain.map((url, i) => (
                <p key={i} className="text-xs text-gray-500 truncate">{i + 1}. {url}</p>
              ))}
            </div>
          )}

          {/* Page intel */}
          {pageIntel?.page_intel_available && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Cell label="Password fields" value={pageIntel.has_password_field ? "Yes ⚠️" : "No"} warn={pageIntel.has_password_field} />
                <Cell label="Login form" value={pageIntel.has_login_form ? "Yes ⚠️" : "No"} warn={pageIntel.has_login_form} />
              </div>

              {pageIntel.hidden_iframes && pageIntel.hidden_iframes.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-red-600 uppercase tracking-wider mb-1.5">Hidden Iframes ({pageIntel.hidden_iframes.length})</p>
                  {pageIntel.hidden_iframes.map((url, i) => (
                    <code key={i} className="block text-xs bg-red-50 text-red-700 rounded px-2 py-1 mb-1 truncate">{url}</code>
                  ))}
                </div>
              )}

              {pageIntel.external_scripts && pageIntel.external_scripts.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">External Scripts ({pageIntel.external_scripts.length})</p>
                  {pageIntel.external_scripts.slice(0, 5).map((url, i) => (
                    <code key={i} className="block text-xs bg-gray-50 text-gray-700 rounded px-2 py-1 mb-1 truncate">{url}</code>
                  ))}
                </div>
              )}
            </>
          )}

          {!screenshot?.screenshot_available && !pageIntel?.page_intel_available && (
            <p className="text-sm text-gray-500">Screenshot and page intelligence not available.</p>
          )}
        </div>
      )}
    </div>
  );
}

function Cell({ label, value, warn }: { label: string; value?: string; warn?: boolean }) {
  return (
    <div>
      <p className="text-[11px] text-gray-400 uppercase tracking-wider">{label}</p>
      <p className={cn("text-sm font-medium mt-0.5 truncate", warn ? "text-red-600" : "text-gray-900")}>{value ?? "—"}</p>
    </div>
  );
}
