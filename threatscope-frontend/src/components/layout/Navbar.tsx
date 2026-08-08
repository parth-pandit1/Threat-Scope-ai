"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, BookOpen, Menu, X, Copy, LogOut } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/context/AuthContext";

export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user, logout } = useAuth();

  const links = [
    { href: "/", label: "Scan" },
    { href: "/dashboard", label: "Dashboard" },
    { href: "/methodology", label: "Methodology" },
  ];

  const handleCopyKey = () => {
    if (user?.api_key) {
      navigator.clipboard.writeText(user.api_key);
      alert("API Key copied to clipboard!");
    }
  };

  return (
    <header className="fixed top-0 inset-x-0 z-50 h-14 border-b border-gray-100 bg-white/80 backdrop-blur-md">
      <div className="page-container flex h-full items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 shadow-sm transition-transform group-hover:scale-105">
            <Shield className="text-white" size={18} />
          </div>
          <span className="text-[15px] font-semibold text-gray-900 tracking-tight">
            ThreatScope<span className="text-brand-600"> AI</span>
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden sm:flex items-center gap-1">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
                pathname === l.href
                  ? "text-brand-600 bg-brand-50"
                  : "text-gray-500 hover:text-gray-900 hover:bg-gray-50",
              )}
            >
              {l.label}
            </Link>
          ))}
        </nav>

        {/* Desktop right */}
        <div className="hidden sm:flex items-center gap-3">
          <a
            href="https://github.com/parth-pandit1/Threat-Scope"
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-50 transition-colors"
            aria-label="GitHub"
          >
            <svg width={18} height={18} viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
          </a>
          <a
            href="/methodology"
            className="p-2 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-50 transition-colors"
            aria-label="Documentation"
          >
            <BookOpen size={18} />
          </a>
          
          {user ? (
            <div className="flex items-center gap-3 pl-3 border-l border-gray-200">
              <span className="flex items-center gap-1.5">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase bg-brand-50 text-brand-600 border border-brand-100 tracking-wide">
                  {user.tier}
                </span>
                <span className="text-xs text-gray-600 max-w-[100px] truncate" title={user.email}>
                  {user.email.split("@")[0]}
                </span>
              </span>
              <button
                onClick={handleCopyKey}
                className="p-1.5 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-50 transition-colors"
                title="Copy API Key"
              >
                <Copy size={14} />
              </button>
              <button
                onClick={logout}
                className="p-1.5 rounded-md text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
                title="Log Out"
              >
                <LogOut size={14} />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 pl-3 border-l border-gray-200">
              <Link
                href="/login"
                className="px-3 py-1.5 rounded-md text-sm font-medium text-gray-500 hover:text-gray-900 transition-colors"
              >
                Sign In
              </Link>
              <Link href="/register" className="btn-primary text-sm px-3 py-1.5">
                Register
              </Link>
            </div>
          )}
        </div>

        {/* Mobile hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="sm:hidden p-2 rounded-md text-gray-500 hover:bg-gray-50"
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="sm:hidden border-t border-gray-100 bg-white px-4 pb-4 pt-2 space-y-2 animate-fade-in">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              onClick={() => setMobileOpen(false)}
              className={cn(
                "block px-3 py-2 rounded-md text-sm font-medium",
                pathname === l.href
                  ? "text-brand-600 bg-brand-50"
                  : "text-gray-600 hover:bg-gray-50",
              )}
            >
              {l.label}
            </Link>
          ))}
          
          {user ? (
            <div className="border-t border-gray-100 pt-2 px-3 space-y-2">
              <div className="flex items-center justify-between py-1">
                <span className="text-xs text-gray-500 truncate">{user.email}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase bg-brand-50 text-brand-600 border border-brand-100">
                  {user.tier}
                </span>
              </div>
              <button
                onClick={() => {
                  handleCopyKey();
                  setMobileOpen(false);
                }}
                className="flex w-full items-center gap-2 px-3 py-2 rounded-md text-sm text-gray-600 hover:bg-gray-50"
              >
                <Copy size={16} /> Copy API Key
              </button>
              <button
                onClick={() => {
                  logout();
                  setMobileOpen(false);
                }}
                className="flex w-full items-center gap-2 px-3 py-2 rounded-md text-sm text-red-600 hover:bg-red-50"
              >
                <LogOut size={16} /> Log Out
              </button>
            </div>
          ) : (
            <div className="border-t border-gray-100 pt-2 grid grid-cols-2 gap-2 px-3">
              <Link
                href="/login"
                onClick={() => setMobileOpen(false)}
                className="flex justify-center items-center px-3 py-2 rounded-md text-sm font-medium text-gray-600 hover:bg-gray-50 border border-gray-200"
              >
                Sign In
              </Link>
              <Link
                href="/register"
                onClick={() => setMobileOpen(false)}
                className="flex justify-center items-center btn-primary text-sm px-3 py-2"
              >
                Register
              </Link>
            </div>
          )}
        </div>
      )}
    </header>
  );
}
