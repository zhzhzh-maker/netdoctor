import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../internal/web/static/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1400,
    rollupOptions: {
      output: {
        manualChunks: {
          vue: ['vue'],
          element: ['element-plus'],
          charts: ['echarts']
        }
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:56789'
    }
  }
})
