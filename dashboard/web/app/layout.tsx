import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import Image from "next/image";
import CommandCenter from "./CommandCenter";
import SensorStatus from "./SensorStatus";
import SystemHealth from "./SystemHealth";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SIS - Resumen de Seguridad",
  description: "Dashboard para un SIEM de entornos OT/IT",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="es"
      className={`${geistSans.variable} ${geistMono.variable} dark antialiased h-full`}
    >
      <body className="min-h-full flex bg-[#111827] text-gray-200">
        <aside className="w-64 flex-shrink-0 bg-[#1a2235] border-r border-gray-800/50 flex flex-col fixed h-full z-10">
          <div className="h-48 flex items-center justify-center p-2 border-b border-gray-800/50 shrink-0">
            <Image
              src="/logo-sis-vertical.png"
              alt="SIS Logo Vertical"
              width={240}
              height={160}
              className="object-contain h-full w-auto"
              priority
            />
          </div>

          <SensorStatus />

          <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
            <Link
              href="/"
              className="block px-3 py-2 text-sm font-medium rounded-md bg-[#5F13CF]/10 text-[#5F13CF] border border-[#5F13CF]/20 transition-colors"
            >
              Dashboard
            </Link>
            <Link
              href="/snort"
              className="block px-3 py-2 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors"
            >
              Alertas Snort
            </Link>
            <Link
              href="/inventario"
              className="block px-3 py-2 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors"
            >
              Inventario OT
            </Link>
          </nav>
          <SystemHealth />
          <CommandCenter />
        </aside>
        <main className="flex-1 ml-64 min-h-screen">{children}</main>
      </body>
    </html>
  );
}
