import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// The build is embedded into the Go binary (backend/internal/web).
// `npm run dev` proxies the API to a panel on :8080.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../backend/internal/web/ui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: { '/api': process.env.CADDYHUB_API || 'http://localhost:8080' },
  },
})
