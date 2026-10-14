import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vitest configured inline (test globals + jsdom).
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
  preview: { port: 4173 },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 800 },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
