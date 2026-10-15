/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        paper: 'rgb(var(--color-paper) / <alpha-value>)',
        raised: 'rgb(var(--color-raised) / <alpha-value>)',
        ink: 'rgb(var(--color-ink) / <alpha-value>)',
        'ink-muted': 'rgb(var(--color-ink-muted) / <alpha-value>)',
        'ink-faint': 'rgb(var(--color-ink-faint) / <alpha-value>)',
        forest: 'rgb(var(--color-forest) / <alpha-value>)',
        'forest-soft': 'rgb(var(--color-forest-soft) / <alpha-value>)',
        lake: 'rgb(var(--color-lake) / <alpha-value>)',
        'lake-soft': 'rgb(var(--color-lake-soft) / <alpha-value>)',
        clay: 'rgb(var(--color-clay) / <alpha-value>)',
        'clay-soft': 'rgb(var(--color-clay-soft) / <alpha-value>)',
        border: 'rgb(var(--color-border) / <alpha-value>)',
      },
      fontFamily: {
        display: ['Fraunces', 'Georgia', 'serif'],
        body: ['"IBM Plex Sans"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}
