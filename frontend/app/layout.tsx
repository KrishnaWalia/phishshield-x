import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "PhishShield X",
  description: "Explainable phishing detection and scam intelligence.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Sidebar />
        <main className="min-h-screen lg:pl-64">
          <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">{children}</div>
        </main>
      </body>
    </html>
  );
}
