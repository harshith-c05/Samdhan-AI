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
        cyber: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          neon: '#00ff66',
          bright: '#10e377',
          glow: 'rgba(0, 255, 102, 0.35)',
        },
        dark: {
          950: '#050709',
          900: '#080b0f',
          850: '#0c1016',
          800: '#111720',
          750: '#161f2c',
          700: '#1d2839',
          600: '#2b394e',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'neon': '0 0 20px -3px rgba(0, 255, 102, 0.25)',
        'neon-lg': '0 0 35px -5px rgba(0, 255, 102, 0.4)',
        'cyber-card': '0 8px 32px 0 rgba(0, 0, 0, 0.6), inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 3s ease-in-out infinite',
        'fadeIn': 'fadeIn 0.25s ease-out both',
        'red-glow': 'redGlowPulse 2s ease-in-out infinite',
      },
      keyframes: {
        scan: {
          '0%, 100%': { transform: 'translateY(0%)' },
          '50%': { transform: 'translateY(100%)' },
        },
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        redGlowPulse: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(239, 68, 68, 0.3)' },
          '50%':       { boxShadow: '0 0 22px rgba(239, 68, 68, 0.6)' },
        },
      }
    },
  },
  plugins: [],
}
