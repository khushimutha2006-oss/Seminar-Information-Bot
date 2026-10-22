import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The API base URL can be overridden at build time with VITE_API_BASE_URL.
// In dev the default is a relative '/api' path proxied to the local backend.
// 127.0.0.1 is used on purpose: "localhost" can resolve to ::1 first, which fails
// when the backend is bound to the IPv4 loopback address only.
// The environment is read through globalThis so the file type-checks without
// pulling in the Node type definitions.
const nodeEnv = (
  globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }
).process?.env;

const API_TARGET = nodeEnv?.VITE_DEV_API_TARGET ?? 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    // A different port would make the documented URL and proxy checks lie.
    strictPort: true,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
