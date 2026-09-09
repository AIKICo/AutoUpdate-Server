---
name: modern-ui-ux-design
description: >-
  Expert guidelines and design tokens for engineering modern, high-density, accessible,
  anti-slop UI/UX interfaces inspired by Linear, Shadcn/ui, Tremor, and Vercel Geist.
  Use when designing dashboards, component systems, dark/light themes, micro-interactions,
  typography, and form UX.
---

# Modern UI/UX Design System Skill (Linear & Shadcn Aesthetic)

This skill guides AI agents in architecting and implementing clean, modern, and production-grade web interfaces. It enforces high visual density, deliberate hierarchy, seamless Dark/Light duality, and eliminates generic "AI slop" patterns.

---

## 1. Core Visual Foundations

### 1.1 Layer Elevation & Surface System
Never use a flat, single background color across an entire application. Construct depth through layered surfaces:
- **Base Background (`--bg-main`)**: Deep, low-saturation canvas (`#090d16` for dark, `#f8fafc` for light).
- **Surface Elevation (`--bg-surface`)**: Secondary container/sidebar layer (`#0f172a` for dark, `#ffffff` for light).
- **Card Background (`--card-bg`)**: Elevated translucent/solid container with subtle contrast (`rgba(18, 26, 47, 0.75)` or `#121a2f`).
- **Subtle Borders (`--card-border`)**: Never use harsh solid gray lines. Always use delicate semi-transparent borders:
  - Dark: `1px solid rgba(255, 255, 255, 0.08)`
  - Light: `1px solid rgba(0, 0, 0, 0.08)`
  - Hover/Focus: `1px solid rgba(99, 102, 241, 0.4)`

### 1.2 Anti-Slop Design Guardrails
AI models frequently default to repetitive tropes that degrade visual quality. Adhere to these strict prohibitions:
- ❌ **Prohibit Cliché Gradients**: No unmotivated diagonal purple-to-cyan or pink-to-orange rainbow backgrounds. Use gradients sparingly and purposefully (e.g., brand accents or active state highlights).
- ❌ **Prohibit Excessive Uniform Padding**: Avoid generic `32px` padding on all elements. Use tight, rhythmic spacing (`8px`, `12px`, `16px`, `20px`, `24px`).
- ❌ **Prohibit Disconnected Color Tokens**: Avoid mixing warm and cold grays. Stick to a cohesive neutral family (Slate / Zinc).
- ❌ **Prohibit Text Centering for Data/Forms**: Align form fields, headers, and data tables to the natural reading edge (Left for LTR, Right for RTL). Center alignment is reserved solely for landing page hero copy or empty-state illustrations.

---

## 2. Component Design Standards

### 2.1 Hybrid Combobox / Select-or-Type Inputs
When an input allows both typing new values and selecting existing ones (e.g., Application Names, Categories, Tags):
1. **Never restrict users to pure dropdowns or pure text fields**: Provide a dual experience.
2. **HTML5 `<datalist>` Autocomplete**: Attach a native `<datalist>` to the text `<input>` so typing filters suggestions instantly.
3. **Quick-Select Pills / Chips**: Render registered items as clickable pill badges (`.app-quick-pill`) underneath or adjacent to the input. Clicking a pill immediately populates the input and updates linked previews.
4. **Live Target Preview**: Provide real-time feedback (e.g., generated URLs, resulting paths) right below the input group as the user types or selects.

### 2.2 Modern Pill Switches (iOS/macOS Style)
For binary states or Dark/Light toggles:
- Use a track-and-thumb pill button (`.theme-switch`, 52px × 28px).
- Provide animated sliding thumbs (`translateX`) with dual contextual icons (Sun ☀️ and Moon 🌙).
- Accompany toggles with human-readable state labels (`Light` / `Dark`) for immediate clarity.

### 2.3 Tables & Data Density (Linear Style)
- Header: Subtle uppercase, tracking (`letter-spacing: 0.05em`), muted color (`--text-muted`), font-size `0.75rem`.
- Rows: Clean row dividers (`1px solid var(--card-border)`), soft hover background highlight (`rgba(255, 255, 255, 0.02)`), and vertical alignment.
- Actions: Group secondary action buttons into compact button groups (`.btn-sm`) with clear hierarchy (Primary, Secondary, Danger).

### 2.4 Micro-Interactions & State Transitions
- **Transitions**: Smooth bezier curves `transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);` on buttons, inputs, pills, and cards.
- **Button Clicks**: Micro scale effect on active press (`:active { transform: scale(0.98); }`).
- **Focus Rings**: Accessible focus outlines (`outline: 2px solid var(--primary); outline-offset: 2px;`).

---

## 3. Typography & Hierarchy
- **System Stack**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif`
- **Monospace Stack**: `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace`
- **Scale**:
  - Headings: `1.5rem` to `1.75rem`, weight `700`, line-height `1.25`
  - Subtitles: `0.875rem` to `0.95rem`, color `--text-muted`, line-height `1.5`
  - Body: `0.875rem` (14px) or `0.9rem`, line-height `1.5`
  - Badges / Micro-copy: `0.72rem` to `0.8rem`, weight `600`

---

## 4. Accessibility & Robustness
1. **Forms**: Always pair `<label>` with `<input>`. Forms submitting via AJAX must have `action="javascript:void(0);"` and `e.preventDefault()`.
2. **Keyboard Navigation**: All interactive elements must be focusable via Tab and activatable with Enter or Space.
3. **Contrast**: Text contrast ratio must meet WCAG 2.1 AA (minimum 4.5:1 for body text).
