import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  build: {
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, "index.html"),
        telegram: path.resolve(__dirname, "telegram.html"),
      },
    },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:7654",
      "/ws":  { target:"ws://127.0.0.1:7654", ws:true }
    }
  }
});
