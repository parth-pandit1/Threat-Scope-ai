"use client";

/* ───────────────────────────────────────────
   ScanForm — File / URL / IP submission
   No auth. No tokens. Just submit and redirect.
   ─────────────────────────────────────────── */

import { useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Upload, Globe, Server, X, FileWarning, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Tab = "file" | "url" | "ip";

export function ScanForm() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("file");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (submit: () => Promise<{ job_id: string }>) => {
    setError(null);
    setLoading(true);
    try {
      const res = await submit();
      router.push(`/scan/${res.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Submission failed");
    } finally {
      setLoading(false);
    }
  };

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: "file", label: "File", icon: <Upload size={14} /> },
    { id: "url", label: "URL", icon: <Globe size={14} /> },
    { id: "ip", label: "IP", icon: <Server size={14} /> },
  ];

  return (
    <div className="card p-6 animate-fade-in">
      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 bg-gray-50 rounded-lg p-1 w-fit">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => { setTab(t.id); setError(null); }}
            className={cn(
              "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-all",
              tab === t.id
                ? "bg-white text-gray-900 shadow-soft"
                : "text-gray-500 hover:text-gray-700",
            )}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg bg-red-50 border border-red-100 px-3.5 py-2.5 text-sm text-red-700 mb-4">
          <span className="h-1.5 w-1.5 rounded-full bg-red-500 shrink-0" />
          {error}
        </div>
      )}

      {/* Content */}
      <div className="max-w-lg">
        {tab === "file" && (
          <FileTab loading={loading} onSubmit={(file) => handleSubmit(() => api.scan.file(file))} />
        )}
        {tab === "url" && (
          <TextInputTab
            loading={loading}
            placeholder="https://example.com"
            buttonLabel="Scan URL"
            onSubmit={(val) => handleSubmit(() => api.scan.url(val))}
            validate={(val) => {
              try { new URL(val.startsWith("http") ? val : `https://${val}`); return null; }
              catch { return "Enter a valid URL"; }
            }}
          />
        )}
        {tab === "ip" && (
          <TextInputTab
            loading={loading}
            placeholder="192.168.1.1 or 2001:db8::1"
            buttonLabel="Scan IP"
            onSubmit={(val) => handleSubmit(() => api.scan.ip(val))}
            validate={(val) => {
              const ip4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val);
              const ip6 = val.includes(":");
              return ip4 || ip6 ? null : "Enter a valid IP address";
            }}
          />
        )}
      </div>
    </div>
  );
}

/* ── File tab ────────────────────────────── */

const MAX_SIZE = 50 * 1024 * 1024;

function FileTab({
  loading,
  onSubmit,
}: {
  loading: boolean;
  onSubmit: (file: File) => void;
}) {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [sizeError, setSizeError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback((f: File) => {
    setSizeError(null);
    if (f.size > MAX_SIZE) {
      setSizeError(`File too large (${(f.size / 1024 / 1024).toFixed(1)} MB). Max 50 MB.`);
      return;
    }
    setFile(f);
  }, []);

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          const f = e.dataTransfer.files?.[0];
          if (f) handleFile(f);
        }}
        onClick={() => !file && inputRef.current?.click()}
        className={cn(
          "relative flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-8 transition-all cursor-pointer",
          dragActive
            ? "border-brand-400 bg-brand-50/50"
            : file
              ? "border-gray-200 bg-gray-50/50"
              : "border-gray-200 bg-white hover:border-gray-300 hover:bg-gray-50/50",
          loading && "opacity-50 pointer-events-none",
        )}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = ""; }}
        />

        {file ? (
          <>
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
              <FileWarning size={20} />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-gray-900 truncate max-w-[260px]">{file.name}</p>
              <p className="text-xs text-gray-500 mt-0.5">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); setFile(null); setSizeError(null); }}
              className="absolute top-3 right-3 p-1 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100"
            >
              <X size={14} />
            </button>
          </>
        ) : (
          <>
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-100 text-gray-400">
              <Upload size={20} />
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-600">
                <span className="font-medium text-brand-600">Click to upload</span> or drag and drop
              </p>
              <p className="text-xs text-gray-400 mt-1">Any file up to 50 MB</p>
            </div>
          </>
        )}
      </div>

      {sizeError && (
        <p className="text-sm text-red-600 flex items-center gap-1.5">
          <span className="h-1 w-1 rounded-full bg-red-500" /> {sizeError}
        </p>
      )}

      {file && (
        <button onClick={() => onSubmit(file)} disabled={loading} className="btn-primary w-full">
          {loading ? <Loader2 size={16} className="animate-spin" /> : null}
          {loading ? "Uploading…" : "Scan file"}
        </button>
      )}
    </div>
  );
}

/* ── Text input tab (URL / IP) ───────────── */

function TextInputTab({
  loading,
  placeholder,
  buttonLabel,
  onSubmit,
  validate,
}: {
  loading: boolean;
  placeholder: string;
  buttonLabel: string;
  onSubmit: (val: string) => void;
  validate: (val: string) => string | null;
}) {
  const [value, setValue] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    const err = validate(trimmed);
    if (err) { setValidationError(err); return; }
    setValidationError(null);
    onSubmit(trimmed);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <input
        type="text"
        value={value}
        onChange={(e) => { setValue(e.target.value); setValidationError(null); }}
        disabled={loading}
        className="input"
        placeholder={placeholder}
      />
      {validationError && (
        <p className="text-sm text-red-600 flex items-center gap-1.5">
          <span className="h-1 w-1 rounded-full bg-red-500" /> {validationError}
        </p>
      )}
      <button type="submit" disabled={loading || !value.trim()} className="btn-primary w-full">
        {loading ? <Loader2 size={16} className="animate-spin" /> : null}
        {loading ? "Submitting…" : buttonLabel}
      </button>
    </form>
  );
}
