import { defineConfig } from "vite";
import { resolve } from "path";
import { copyFileSync, mkdirSync, existsSync } from "fs";
import { build as esbuild } from "esbuild";

export default defineConfig({
  root: resolve(__dirname),
  build: {
    outDir: resolve(__dirname, "../dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "src/ui/popup.html"),
        offscreen: resolve(__dirname, "src/background/offscreen.html"),
        "service-worker": resolve(__dirname, "src/background/service-worker.ts"),
        collector: resolve(__dirname, "src/content/collector.ts"),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === "service-worker") return "service-worker.js";
          if (chunkInfo.name === "collector") return "collector.js";
          return "[name].js";
        },
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name].[ext]",
      },
    },
  },
  plugins: [
    {
      name: "copy-manifest-and-assets",
      async closeBundle() {
        const distDir = resolve(__dirname, "../dist");
        if (!existsSync(distDir)) mkdirSync(distDir, { recursive: true });

        // Copy manifest.json
        const manifestSrc = resolve(__dirname, "manifest.json");
        if (existsSync(manifestSrc)) {
          copyFileSync(manifestSrc, resolve(distDir, "manifest.json"));
        }

        // Copy rules if present
        const rulesSrc = resolve(__dirname, "src/background/dnr-rules.json");
        if (existsSync(rulesSrc)) {
          copyFileSync(rulesSrc, resolve(distDir, "dnr-rules.json"));
        }

        // Copy onnx assets if present
        const assetOnnx = resolve(__dirname, "assets/model.onnx");
        if (existsSync(assetOnnx)) {
          const assetsDist = resolve(distDir, "assets");
          if (!existsSync(assetsDist)) mkdirSync(assetsDist, { recursive: true });
          copyFileSync(assetOnnx, resolve(assetsDist, "model.onnx"));
        }

        // Emit a self-contained content script bundle so runtime execution does not depend on chunk imports.
        await esbuild({
          entryPoints: [resolve(__dirname, "src/content/collector.ts")],
          bundle: true,
          format: "iife",
          platform: "browser",
          target: ["chrome109"],
          minify: true,
          outfile: resolve(distDir, "collector.js"),
          legalComments: "none",
        });
      },
    },
  ],
  resolve: {
    alias: {
      "@core": resolve(__dirname, "src/core"),
      "@messaging": resolve(__dirname, "src/messaging"),
    },
  },
});
