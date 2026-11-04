import { defineConfig, loadEnv } from 'vite';
import type { ProxyOptions } from 'vite';

// The browser never holds the Meta API key. Same-origin /api/muse/* requests
// are proxied to the Meta API, and the server adds
// `Authorization: Bearer $MUSE_API_KEY` from its own environment
// (playground/.env.local, gitignored — see playground/.env.example).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const museKey = env['MUSE_API_KEY'] ?? process.env['MUSE_API_KEY'] ?? '';
  const museProxy: ProxyOptions = {
    target: 'https://api.meta.ai/v1',
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api\/muse/, ''),
    configure: (proxy) => {
      proxy.on('proxyReq', (proxyReq) => {
        if (museKey) proxyReq.setHeader('Authorization', `Bearer ${museKey}`);
      });
    },
  };
  return {
    define: {
      // Presence only — the key itself is never exposed to the client.
      __MUSE_AVAILABLE__: JSON.stringify(museKey !== ''),
    },
    // Serve the real package's files unbundled so its `new URL(..., import.meta.url)`
    // wasm reference resolves to the file on disk.
    optimizeDeps: { exclude: ['@colophon/core'] },
    server: {
      port: 5173,
      proxy: { '/api/muse': museProxy },
    },
    preview: {
      port: 4173,
      proxy: { '/api/muse': museProxy },
    },
    build: {
      outDir: 'dist',
      target: 'es2022',
    },
  };
});
