"use client";

import { X, CheckCircle, AlertCircle, Info } from "lucide-react";
import type { Toast as ToastType } from "@/hooks/useToast";

interface Props {
  toasts: ToastType[];
  onRemove: (id: string) => void;
}

const icons = {
  success: <CheckCircle size={16} className="text-emerald-500" />,
  error: <AlertCircle size={16} className="text-red-500" />,
  info: <Info size={16} className="text-brand-500" />,
};

const bgColors = {
  success: "bg-emerald-50 border-emerald-200",
  error: "bg-red-50 border-red-200",
  info: "bg-blue-50 border-blue-200",
};

export function ToastContainer({ toasts, onRemove }: Props) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`animate-toast-in flex items-center gap-2.5 rounded-lg border px-4 py-3 shadow-card ${bgColors[toast.type]}`}
        >
          {icons[toast.type]}
          <p className="text-sm text-gray-700 flex-1">{toast.message}</p>
          <button
            onClick={() => onRemove(toast.id)}
            className="p-0.5 rounded text-gray-400 hover:text-gray-600"
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}
