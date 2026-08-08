import { withSentryConfig } from "@sentry/nextjs";

/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8000/api/:path*",
      },
    ];
  },
};

export default withSentryConfig(nextConfig, {
  silent: true,
  org: "threatscope",
  project: "threatscope-frontend",
  widenClientFileUpload: true,
  hideSourceMaps: true,
});
