import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#050a14", 900: "#08101e", 800: "#0c1526", 700: "#12203a", 600: "#1a2b4a" },
        line: "#1c2b47",
        signal: { DEFAULT: "#4cc9f0", dim: "#2a8fb0" },
      },
      fontFamily: {
        // Bahnschrift ships with Windows 10+; falls back gracefully elsewhere.
        display: ['"Bahnschrift"', '"Segoe UI Variable Display"', "system-ui", "sans-serif"],
        sans: ['"Segoe UI Variable Text"', '"Segoe UI"', "system-ui", "sans-serif"],
        mono: ['"Cascadia Mono"', "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
