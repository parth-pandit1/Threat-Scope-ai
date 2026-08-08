import { Shield } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-gray-100 bg-white mt-16">
      <div className="page-container py-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <Shield size={14} />
            <span>ThreatScope AI</span>
            <span className="text-gray-300">·</span>
            <span>Threat Intelligence Platform</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-gray-500">
            <a href="/methodology" className="hover:text-blue-600 transition-colors">Methodology</a>
            <a href="/changelog" className="hover:text-blue-600 transition-colors">Changelog</a>
            <a href="mailto:support@threatscope.ai" className="hover:text-blue-600 transition-colors">Report Issue</a>
          </div>
        </div>
        <div className="mt-4 text-center md:text-left text-xs text-gray-400">
          Built for cybersecurity research and education
        </div>
      </div>
    </footer>
  );
}
