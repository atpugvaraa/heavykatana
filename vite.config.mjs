import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: true,
    port: 8080,
    strictPort: true,
    cors: true,
  },
  preview: {
    host: true,
    port: 8080,
    strictPort: true,
  },
  build: {
    sourcemap: true,
  },
});
