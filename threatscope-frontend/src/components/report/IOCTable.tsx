"use client";

import { useState } from "react";
import { Network, ChevronDown } from "lucide-react";
import type { IOCResult } from "@/types";
import { cn } from "@/lib/utils";

interface Props { data: IOCResult }

export function IOCTable({ data }: Props) {
  const [open, setOpen] = useState(data.total_ioc_count > 0);

  const sections: { label: string; items: string[] }[] = [
    { label: "IPv4 Addresses", items: data.ipv4 },
    { label: "Domains", items: data.domains },
    { label: "URLs", items: data.urls },
    { label: "Emails", items: data.emails },
    { label: "MD5 Hashes", items: data.hashes?.md5 ?? [] },
    { label: "SHA-256 Hashes", items: data.hashes?.sha256 ?? [] },
    { label: "Registry Keys", items: data.registry_keys },
    { label: "File Paths", items: data.file_paths },
    { label: "Mutexes", items: data.mutexes },
    { label: "CVEs", items: data.cves },
    { label: "MITRE Techniques", items: data.mitre_techniques },
    { label: "Bitcoin Wallets", items: data.crypto_wallets?.bitcoin ?? [] },
  ].filter((s) => s.items.length > 0);

  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-50 text-gray-500 shrink-0">
          <Network size={16} />
        </div>
        <span className="flex-1 text-sm font-semibold text-gray-900">IOC Extraction</span>
        <span className="text-xs text-gray-500 font-medium mr-2">{data.total_ioc_count} indicator{data.total_ioc_count !== 1 ? "s" : ""}</span>
        <ChevronDown size={16} className={cn("text-gray-400 transition-transform duration-200", open && "rotate-180")} />
      </button>

      {open && (
        <div className="border-t border-gray-50 px-5 py-4">
          {sections.length === 0 ? (
            <p className="text-sm text-gray-500">No indicators of compromise found.</p>
          ) : (
            <div className="space-y-4">
              {sections.map((s) => (
                <div key={s.label}>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">{s.label} ({s.items.length})</p>
                  <div className="space-y-1">
                    {s.items.slice(0, 10).map((item, i) => (
                      <code key={i} className="block text-xs bg-gray-50 text-gray-700 rounded px-2 py-1 truncate">{item}</code>
                    ))}
                    {s.items.length > 10 && <p className="text-xs text-gray-400">+{s.items.length - 10} more</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
