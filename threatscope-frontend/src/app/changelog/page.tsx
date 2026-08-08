"use client";

import { Calendar, CheckCircle2 } from "lucide-react";

export default function ChangelogPage() {
  const releases = [
    {
      version: "v1.0.0-beta.2",
      date: "July 27, 2026",
      status: "Latest Release",
      isLatest: true,
      changes: [
        "Fixed critical routing prefix mismatch for the file scan pipeline endpoint (/api/scan/file).",
        "Set up robust CI/CD workflow testing backend pytest suite, type-checking frontend Next.js, and running Docker Compose integration smoke tests.",
        "Replaced silent error swallowing on the dashboard and methodology pages with user-friendly retry banners and error details.",
        "Fully documented all undocumented application environment variables (CORS_ORIGINS, MINIO_PUBLIC_URL, YARA_BASE_DIR, COMPILED_RULES_PATH) in .env.example.",
        "Corrected obsolete code documentation referencing deleted authentication modules and legacy yara engines."
      ]
    },
    {
      version: "v1.0.0-beta.1",
      date: "June 15, 2026",
      status: "Initial Beta",
      isLatest: false,
      changes: [
        "Implemented high-performance file and URL scanning pipelines utilizing FastAPI and Next.js.",
        "Integrated community-curated YARA rules and automated weekly update sync task.",
        "Added static PE file structural analysis (section entropy, imports, and obfuscation patterns) using LIEF.",
        "Built detailed live health-monitoring metrics tracking PostgreSQL, Redis, MinIO, Ollama, and YARA compiler status.",
        "Configured asynchronous background processing queue using Redis and RQ workers.",
        "Added local AI explanation model integration using Ollama / Mistral."
      ]
    }
  ];

  return (
    <div className="page-container py-12">
      <div className="max-w-3xl mx-auto space-y-12">
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight text-gray-900">Changelog</h1>
          <p className="text-lg text-gray-500 max-w-lg mx-auto">
            Stay up to date with the latest features, improvements, and bug fixes applied to ThreatScope AI.
          </p>
        </div>

        <div className="relative border-l border-gray-200 ml-4 md:ml-6 space-y-12">
          {releases.map((release) => (
            <div key={release.version} className="relative pl-8 sm:pl-10">
              {/* Timeline dot */}
              <div className={`absolute -left-[11px] top-1.5 flex h-5 w-5 items-center justify-center rounded-full border bg-white ${
                release.isLatest ? "border-brand-600 ring-4 ring-brand-50" : "border-gray-300"
              }`}>
                <div className={`h-2.5 w-2.5 rounded-full ${release.isLatest ? "bg-brand-600" : "bg-gray-400"}`} />
              </div>

              {/* Card content */}
              <div className="card p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="text-xl font-bold text-gray-900">{release.version}</span>
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                      release.isLatest 
                        ? "bg-brand-50 text-brand-700 border border-brand-100" 
                        : "bg-gray-50 text-gray-600 border border-gray-100"
                    }`}>
                      {release.status}
                    </span>
                  </div>
                  <div className="flex items-center text-sm text-gray-400 gap-1.5">
                    <Calendar size={14} />
                    <span>{release.date}</span>
                  </div>
                </div>

                <ul className="space-y-3">
                  {release.changes.map((change, idx) => (
                    <li key={idx} className="flex items-start gap-3">
                      <CheckCircle2 className="text-emerald-500 shrink-0 mt-0.5" size={16} />
                      <span className="text-sm text-gray-600 leading-relaxed">{change}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
