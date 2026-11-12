import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development the API runs separately (make run-api); proxy it so the app
// can use relative /api URLs in every environment.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': process.env.VULNVIZ_API ?? 'http://localhost:8080' },
  },
  build: { outDir: 'dist', sourcemap: false },
})
