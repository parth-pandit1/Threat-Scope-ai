import type { Metadata } from "next";
import "./globals.css";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { AuthProvider } from "@/context/AuthContext";

export const metadata: Metadata = {
  title: "ThreatScope AI — Threat Intelligence Platform",
  description:
    "Upload files or submit URLs for deep malware analysis, YARA scanning, and AI-powered threat explanations.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col bg-gray-50/50">
        <AuthProvider>
          <Navbar />
          <main className="flex-1 pt-14">{children}</main>
          <Footer />
        </AuthProvider>
      </body>
    </html>
  );
}
