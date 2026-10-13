import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// The build is embedded into the Rust binary (backend/src/web.rs).
// `npm run dev` proxies the API to a panel on :8080.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../backend/ui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: { '/api': process.env.CADDYMIUM_API || 'http://localhost:8080' },
  },
})
