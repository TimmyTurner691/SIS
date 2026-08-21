import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import Image from "next/image";
import CommandCenter from "./CommandCenter";
import SensorStatus from "./SensorStatus";
import SystemHealth from "./SystemHealth";
import ServiceStatus from "./ServiceStatus";
import AlertConfig from "./AlertConfig";
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
  description: "Dashboard para un SIEM de entornos OT",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className={`${geistSans.variable} ${geistMono.variable} dark antialiased h-full`}>
      <body className="min-h-full flex bg-[#111827] text-gray-200">

        {/* SIDEBAR LATERAL */}
        <aside className="w-64 flex-shrink-0 bg-[#1a2235] border-r border-gray-800/50 flex flex-col fixed h-full z-20">

          {/* CONTENEDOR DEL LOGO CORREGIDO */}
          <div className="h-36 flex items-center justify-center p-4 border-b border-gray-800/50 shrink-0">
            <Image
              src="/logo-sis-vertical.png"
              alt="SIS Logo Vertical"
              width={220}
              height={120}
              className="object-contain w-full h-full hover:scale-105 transition-transform duration-300"
              priority
            />
          </div>

          {/* Navegación y Configuración */}
          <nav className="flex-1 px-4 pt-8 pb-4 overflow-y-auto flex flex-col">
            <div className="space-y-1">
              <Link href="/" className="block px-3 py-1.5 text-sm font-medium rounded-md bg-[#5F13CF]/10 text-[#5F13CF] border border-[#5F13CF]/20 transition-colors">
                Dashboard
              </Link>
              <Link href="/snort" className="block px-3 py-1.5 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors">
                Alertas Snort
              </Link>
              <Link href="/inventario" className="block px-3 py-1.5 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors">
                Inventario OT
              </Link>
              <Link href="/scada" className="block px-3 py-1.5 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors">
                Telemetría SCADA
              </Link>
              <Link href="/raw" className="block px-3 py-1.5 text-sm font-medium rounded-md hover:bg-[#5F13CF]/10 text-gray-400 hover:text-[#5F13CF] transition-colors">
                Logs Raw
              </Link>
            </div>

            {/* Configuración de correo */}
            <div className="mt-5 pt-4 border-t border-gray-800/50">
              <AlertConfig />
            </div>
          </nav>

          {/* Estado de Elasticsearch y Salud del Sistema al fondo */}
          <div className="mt-auto pt-4 pb-2">
            <ServiceStatus />
            <SystemHealth />
          </div>
        </aside>

        {/* CONTENEDOR PRINCIPAL */}
        <div className="flex-1 ml-64 flex flex-col min-h-screen">

          {/* BARRA SUPERIOR (Navbar) */}
          <header className="h-16 bg-[#1a2235]/90 backdrop-blur border-b border-gray-800/50 flex items-center justify-between px-6 sticky top-0 z-10 shadow-sm">
            <SensorStatus />
            <CommandCenter />
          </header>

          {/* CONTENIDO DE LAS PÁGINAS */}
          <main className="flex-1 p-6">
            {children}
          </main>
        </div>

      </body>
    </html>
  );
}