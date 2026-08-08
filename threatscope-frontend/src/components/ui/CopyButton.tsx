"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

interface Props {
  text: string;
  className?: string;
}

export function CopyButton({ text, className }: Props) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Fallback for non-secure contexts
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={`p-1 rounded text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors ${className ?? ""}`}
      aria-label="Copy to clipboard"
    >
      {copied ? (
        <Check size={13} className="text-emerald-500" />
      ) : (
        <Copy size={13} />
      )}
    </button>
  );
}
