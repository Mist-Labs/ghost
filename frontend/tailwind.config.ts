import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        body: [
          "Inter",
          "SF Pro Text",
          "Segoe UI",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        display: [
          "Inter",
          "SF Pro Display",
          "Segoe UI",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: ["SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      colors: {
        void: "#050607",
        surface: "#090d10",
        raised: "#0e1418",
        hover: "#131c22",
        signal: "#00e676",
        border: "rgba(255,255,255,0.09)",
        "border-strong": "rgba(255,255,255,0.16)",
        "text-1": "#e6ebf0",
        "text-2": "#8b96a1",
        "text-3": "#4e5a63",
      },
      boxShadow: {
        signal: "0 0 28px rgba(0, 230, 118, 0.22)",
        panel: "0 24px 64px rgba(0, 0, 0, 0.35)",
      },
      animation: {
        pulseDot: "pulseDot 1.8s ease-in-out infinite",
        scan: "scan 7s linear infinite",
        floatGrid: "floatGrid 18s linear infinite",
      },
      keyframes: {
        pulseDot: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(300%)" },
        },
        floatGrid: {
          "0%": { transform: "translate3d(0, 0, 0)" },
          "50%": { transform: "translate3d(12px, 18px, 0)" },
          "100%": { transform: "translate3d(0, 0, 0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
