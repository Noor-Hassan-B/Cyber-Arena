/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0B0F19',
          card: '#111827',
          cardLight: '#1F2937',
          border: '#1E293B',
          accent: '#3B82F6',
          danger: '#EF4444',
          warning: '#F59E0B',
          success: '#10B981',
          purple: '#8B5CF6',
          cyan: '#06B6D4'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
