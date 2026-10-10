import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const api = { target: 'http://localhost:8000', changeOrigin: true }
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/v1': api, '/demo': api, '/attacker': api } },
})
