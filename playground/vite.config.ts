import { defineConfig } from 'vite';

// Dev proxy so the in-tab agent can reach the default Llama API base URL
// without a CORS preflight failure. Only used when the configured base URL
// is the default (see src/agent.ts endpointForBaseURL).
export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      '/llama-api': {
        target: 'https://api.llama.com/compat/v1',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llama-api/, ''),
      },
    },
  },
  build: {
    outDir: 'dist',
    target: 'es2022',
  },
});
