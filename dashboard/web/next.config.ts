import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  devIndicators: false,
  serverExternalPackages: ["dockerode"],
  typescript: {
    // Permite que el build termine con éxito incluso si hay errores de TypeScript
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
