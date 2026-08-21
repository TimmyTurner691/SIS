import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Image from "next/image";
import SidebarNav from "./components/SidebarNav";
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
      <body className="min-h-full flex bg-[#0f172a] text-gray-200">

        {/* SIDEBAR LATERAL */}
        <aside className="w-64 flex-shrink-0 bg-[#1e293b] border-r border-slate-700/50 flex flex-col fixed h-full z-20">

          {/* CONTENEDOR DEL LOGO */}
          <div className="h-40 flex items-center justify-center p-3 border-b border-slate-700/50 bg-[#0f172a]/50 shrink-0">
            <Image
              src="/logo-sis-vertical.png"
              alt="SIS Logo Vertical"
              width={220}
              height={140}
              className="object-contain w-full h-full hover:scale-105 transition-transform duration-300"
              priority
              unoptimized
            />
          </div>

          {/* Navegación y Configuración */}
          <nav className="flex-1 px-4 pt-4 pb-4 overflow-y-auto flex flex-col">
            <SidebarNav />

            {/* Configuración de correo */}
            <div className="mt-5 pt-4 border-t border-slate-700/50">
              <AlertConfig />
            </div>
          </nav>

          {/* Estado de Elasticsearch y Salud del Sistema al fondo */}
          <div className="mt-auto pt-4 pb-2 bg-[#0f172a]/30 border-t border-slate-700/50">
            <ServiceStatus />
            <SystemHealth />
          </div>
        </aside>

        {/* CONTENEDOR PRINCIPAL */}
        <div className="flex-1 ml-64 flex flex-col min-h-screen">

          {/* BARRA SUPERIOR (Navbar) */}
          <header className="h-16 bg-[#1e293b] border-b border-slate-700/50 flex items-center justify-between px-6 sticky top-0 z-10 shadow-sm">
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