import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  devIndicators: false,
  typescript: {
    // Permite que el build termine con éxito incluso si hay errores de TypeScript
    ignoreBuildErrors: true,
  },
  eslint: {
    // Permite que el build termine con éxito incluso si hay errores de ESLint
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;
