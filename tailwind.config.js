/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0B1220",
        surface: "#121B2E",
        surface2: "#182238",
        line: "#26314A",
        text: "#E4E9F2",
        muted: "#7C8AA5",
        signal: "#E8A33D",
        critical: "#E23D28",
        safe: "#2FBF9F",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'IBM Plex Sans'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
    },
  },
  plugins: [],
};
