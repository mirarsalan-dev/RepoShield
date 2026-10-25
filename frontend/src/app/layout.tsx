import type { Metadata } from "next";
import { Suspense } from "react";
import "./globals.css";
import { Sidebar } from "@/components/navigation/Sidebar";
import { Header } from "@/components/navigation/Header";
import { SectionNav } from "@/components/navigation/SectionNav";
import { ThemeProvider } from "@/components/common/ThemeContext";
import { SidebarProvider } from "@/components/navigation/SidebarContext";
import { ToastProvider } from "@/components/common/ToastProvider";
import { PageTransition } from "@/components/motion";

export const metadata: Metadata = {
  title: "RepoShield — macOS Cybersecurity Intelligence Platform",
  description: "Native macOS-inspired developer security analyzer. Static code analysis, secret detection, and dependency vulnerability intelligence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem("reposhield_theme");var d=t==="dark"||(!t&&window.matchMedia("(prefers-color-scheme: dark)").matches)||(t==="system"&&window.matchMedia("(prefers-color-scheme: dark)").matches);if(d){document.documentElement.classList.add("dark");document.documentElement.setAttribute("data-theme","dark");}else{document.documentElement.classList.remove("dark");document.documentElement.setAttribute("data-theme","light");}}catch(e){}})();`,
          }}
        />
      </head>
      <body
        className="bg-[var(--background)] text-[var(--foreground-primary)] min-h-screen flex antialiased"
        suppressHydrationWarning
      >
        <ThemeProvider>
          <ToastProvider>
            <SidebarProvider>
              <div className="flex w-full min-h-screen">
                <Sidebar />
                <div className="flex-1 flex flex-col min-w-0 bg-[var(--background)]">
                  <Header />
                  <SectionNav />
                  <main className="flex-1 px-7 md:px-9 py-6 md:py-8 max-w-7xl w-full mx-auto space-y-6">
                    <Suspense
                      fallback={
                        <div className="text-xs text-[var(--foreground-secondary)] font-mono p-4">
                          Loading content...
                        </div>
                      }
                    >
                      <PageTransition>{children}</PageTransition>
                    </Suspense>
                  </main>
                </div>
              </div>
            </SidebarProvider>
          </ToastProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
