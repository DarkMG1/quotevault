/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          400: '#a78bfa',
          500: '#8b5cf6',
          600: '#7c3aed',
          900: '#4c1d95',
        },
        background: '#0f172a',
        surface: '#1e293b',
        'surface-hover': '#334155',
        'text-main': '#f8fafc',
        'text-muted': '#94a3b8',
      }
    },
  },
  plugins: [],
}
