"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { HealthStatus } from "@/types";
import { Shield, Globe, FileText, Cpu, Eye, Activity } from "lucide-react";

export default function MethodologyPage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = () => {
    setLoading(true);
    setError(null);
    api.health()
      .then((data) => {
        setHealth(data);
        setError(null);
      })
      .catch(() => {
        setError("Failed to check platform health");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="page-container py-12">
      <div className="max-w-4xl mx-auto space-y-12">
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight text-gray-900">Analysis Methodology</h1>
          <p className="text-lg text-gray-500 max-w-2xl mx-auto">
            How ThreatScope AI analyzes files and URLs to detect malicious behavior and provide threat scores.
          </p>
        </div>

        <section className="space-y-6">
          <div className="flex items-center gap-3 border-b border-gray-100 pb-2">
            <Activity className="text-brand-600" size={24} />
            <h2 className="text-2xl font-semibold text-gray-900">Threat Score (0-100)</h2>
          </div>
          <div className="card p-6">
            <p className="text-gray-600 mb-4">
              The overall threat score is calculated by aggregating signals from multiple detection modules. The score ranges from 0 (clean) to 100 (highly malicious).
            </p>
            <ul className="space-y-3 text-sm text-gray-700">
              <li className="flex items-start gap-2"><span className="font-semibold text-gray-900 w-32 shrink-0">YARA Rules:</span> Up to +50 points</li>
              <li className="flex items-start gap-2"><span className="font-semibold text-gray-900 w-32 shrink-0">VirusTotal:</span> Up to +40 points (scales with detection ratio)</li>
              <li className="flex items-start gap-2"><span className="font-semibold text-gray-900 w-32 shrink-0">PE Analysis:</span> Up to +30 points (suspicious sections, entropy, imports)</li>
              <li className="flex items-start gap-2"><span className="font-semibold text-gray-900 w-32 shrink-0">String Extraction:</span> Up to +15 points (base64, obfuscation patterns)</li>
              <li className="flex items-start gap-2"><span className="font-semibold text-gray-900 w-32 shrink-0">SSL/DNS:</span> Up to +20 points (self-signed, expired, suspicious TLDs)</li>
            </ul>
            <p className="text-xs text-gray-500 mt-4 italic">Scores are capped at 100. A score &ge; 75 is considered Malicious.</p>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-3 border-b border-gray-100 pb-2">
            <Shield className="text-brand-600" size={24} />
            <h2 className="text-2xl font-semibold text-gray-900">YARA Scanning</h2>
          </div>
          <div className="card p-6 space-y-4">
            <p className="text-gray-600">
              We compile and evaluate files against community-curated YARA rules targeting known malware families, packers, and suspicious byte sequences.
            </p>
            <div className="bg-gray-50 rounded-lg p-4 flex flex-col sm:flex-row gap-4 justify-between items-center">
              <div>
                <p className="text-sm font-semibold text-gray-900">Live Engine Status</p>
                <p className="text-xs text-gray-500 mt-1">Rules are automatically synchronized weekly.</p>
              </div>
              <div className="text-right flex flex-col items-end">
                {loading ? (
                  <p className="text-sm text-gray-500">Loading status...</p>
                ) : error ? (
                  <div className="flex flex-col items-end gap-1">
                    <span className="text-sm text-red-600 font-medium">{error}</span>
                    <button
                      onClick={fetchHealth}
                      className="text-xs text-brand-600 hover:text-brand-700 underline focus:outline-none"
                    >
                      Retry
                    </button>
                  </div>
                ) : health?.yara ? (
                  <>
                    <p className="text-lg font-bold text-gray-900">{health.yara.rule_count.toLocaleString()} rules</p>
                    <p className="text-xs text-gray-500">Updated: {health.yara.last_updated.split("T")[0]}</p>
                  </>
                ) : (
                  <p className="text-sm text-gray-500">Status unavailable</p>
                )}
              </div>
            </div>
            <p className="text-sm text-gray-600">Primary sources include the Neo23x0/signature-base repository and the Yara-Rules project.</p>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-3 border-b border-gray-100 pb-2">
            <Cpu className="text-brand-600" size={24} />
            <h2 className="text-2xl font-semibold text-gray-900">PE Analysis (Windows Executables)</h2>
          </div>
          <div className="card p-6">
            <p className="text-gray-600 mb-4">
              For Windows Portable Executables (PE), we perform deep static analysis using LIEF to uncover structural anomalies:
            </p>
            <ul className="list-disc pl-5 space-y-2 text-sm text-gray-700">
              <li><strong>Section Anomalies:</strong> Checking for writable & executable (WX) sections and abnormally high entropy (indicative of packing/encryption).</li>
              <li><strong>Import Table (IAT):</strong> Flagging suspicious API calls (e.g., VirtualAlloc, WriteProcessMemory, CreateRemoteThread).</li>
              <li><strong>Overlay Data:</strong> Detecting appended data past the end of the formal PE structure, often used to hide payloads.</li>
              <li><strong>Timestamps:</strong> Identifying forged compilation dates (e.g., Unix epoch 0 or future dates).</li>
            </ul>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-3 border-b border-gray-100 pb-2">
            <Globe className="text-brand-600" size={24} />
            <h2 className="text-2xl font-semibold text-gray-900">VirusTotal & External Intelligence</h2>
          </div>
          <div className="card p-6 bg-amber-50/30 border-amber-100">
            <p className="text-gray-700 mb-4">
              We optionally query file hashes against VirusTotal to fetch community detection ratios and popular threat names.
            </p>
            <div className="flex items-start gap-3 bg-white p-4 rounded-md border border-amber-200">
              <Eye className="text-amber-600 shrink-0 mt-0.5" size={18} />
              <p className="text-sm text-amber-900 leading-relaxed">
                <strong>Data Sharing Notice:</strong> If a file is not found in VirusTotal, we may upload it for analysis. 
                VirusTotal shares uploaded files with the global security community. Do not submit files containing confidential or PII data.
              </p>
            </div>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-3 border-b border-gray-100 pb-2">
            <FileText className="text-brand-600" size={24} />
            <h2 className="text-2xl font-semibold text-gray-900">Data Handling & Privacy</h2>
          </div>
          <div className="card p-6">
            <p className="text-sm text-gray-700 leading-relaxed">
              Uploaded files are stored temporarily for analysis and are <strong>automatically deleted after 7 days</strong>. 
              Raw files are never shared with third parties (with the exception of VirusTotal, as noted above).
              Our AI explanation module utilizes local, on-premise models (Ollama/Mistral) — your file metadata is never sent to cloud LLM providers.
            </p>
          </div>
        </section>

      </div>
    </div>
  );
}
