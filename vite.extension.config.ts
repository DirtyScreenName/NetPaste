import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  publicDir: 'extension/public',
  build: {
    outDir: 'dist-extension',
    emptyOutDir: true,
    modulePreload: false,
    rollupOptions: {
      input: {
        sidepanel: 'sidepanel.html',
        'service-worker': 'src/extension/serviceWorker.ts'
      },
      output: {
        entryFileNames: (chunkInfo) =>
          chunkInfo.name === 'service-worker'
            ? 'service-worker.js'
            : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]'
      }
    }
  }
});
