"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

interface NavItemProps {
  href: string;
  children: React.ReactNode;
}

function NavItem({ href, children }: NavItemProps) {
  const pathname = usePathname();
  const isActive = pathname === href;

  return (
    <Link
      href={href}
      className={
        isActive
          ? "block px-4 py-2.5 text-sm font-medium rounded-r-lg transition-all duration-200 border-l-4 bg-[#0ea5e9]/10 border-[#0ea5e9] text-[#38bdf8] shadow-[inset_4px_0_0_0_#0ea5e9]"
          : "block px-4 py-2.5 text-sm font-medium rounded-r-lg transition-all duration-200 border-l-4 border-transparent text-gray-400 hover:bg-slate-800/50 hover:border-slate-500 hover:text-gray-200"
      }
    >
      {children}
    </Link>
  );
}

export default function SidebarNav() {
  return (
    <div className="space-y-1">
      <NavItem href="/">Fusión de riesgos</NavItem>
      <NavItem href="/ids">IDS</NavItem>
      <NavItem href="/red">Red</NavItem>
      <NavItem href="/scada">SCADA</NavItem>
      <NavItem href="/equipos-descubiertos">Equipos Descubiertos</NavItem>
      <NavItem href="/activos-registrados">Activos Registrados</NavItem>
      <NavItem href="/firmas">Firmas / Reglas</NavItem>
      <NavItem href="/raw">Audit Logs</NavItem>
    </div>
  );
}
