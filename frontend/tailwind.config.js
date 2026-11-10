/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "var(--bg-canvas)",
        surface: "var(--bg-surface)",
        "surface-elevated": "var(--bg-surface-elevated)",
        border: "var(--border-subtle)",
        foreground: "var(--text-primary)",
        muted: "var(--text-muted)",
        primary: {
          DEFAULT: "var(--btn-primary-bg)",
          foreground: "var(--btn-primary-fg)",
        },
        secondary: {
          DEFAULT: "var(--accent-blue)",
          foreground: "#FFFFFF",
        },
        accent: {
          blue: "#2563EB",
          cyan: "#06B6D4",
          green: "#16A34A",
          amber: "#D97706",
          red: "#DC2626",
        },
        risk: {
          low: "#16A34A",
          medium: "#D97706",
          high: "#EA580C",
          critical: "#DC2626",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
