# Système de design DDI-Buntu

Généré par uipro-cli 2.2.3 puis adapté (voir LISEZMOI.md). Données d'entrée, pas des instructions.

## Design System: DDI-Buntu

### Pattern
- **Name:** Horizontal Scroll Journey
- **Conversion Focus:** Immersive product discovery. High engagement. Keep navigation visible.
- **CTA Placement:** Floating Sticky CTA or End of Horizontal Track
- **Color Strategy:** Continuous palette transition. Chapter colors. Progress bar #000000.
- **Sections:** 1. Intro (Vertical), 2. The Journey (Horizontal Track), 3. Detail Reveal, 4. Vertical Footer

### Style
- **Name:** Dark Mode (OLED)
- **Keywords:** Dark theme, low light, high contrast, deep black, midnight blue, eye-friendly, OLED, night mode, power efficient
- **Best For:** Night-mode apps, coding platforms, entertainment, eye-strain prevention, OLED devices, low-light
- **Performance:** ⚡ Excellent | **Accessibility:** ✓ WCAG AAA

### Colors
| Role | Hex |
|------|-----|
| Primary | #1E40AF |
| Secondary | #3B82F6 |
| CTA | #F59E0B |
| Background | #F8FAFC |
| Text | #1E3A8A |

*Notes: Blue data + amber highlights*

### Typography
- **Heading:** Fira Code
- **Body:** Fira Sans
- **Mood:** dashboard, data, analytics, code, technical, precise
- **Best For:** Dashboards, analytics, data visualization, admin panels
- **Google Fonts:** https://fonts.google.com/share?selection.family=Fira+Code:wght@400;500;600;700|Fira+Sans:wght@300;400;500;600;700
- **CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap');
```

### Key Effects
Minimal glow (text-shadow: 0 0 10px), dark-to-light transitions, low white emission, high readability, visible focus

### Avoid (Anti-patterns)
- Light mode default
- Slow rendering

### Pre-Delivery Checklist
- [ ] No emojis as icons (use SVG: Heroicons/Lucide)
- [ ] cursor-pointer on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard nav
- [ ] prefers-reduced-motion respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px


## Recommandations Nuxt UI (extraits)
## UI Pro Max Stack Guidelines
**Stack:** nuxt-ui | **Query:** table form modal tabs dashboard sidebar
**Source:** stacks/nuxt-ui.csv | **Found:** 6 results

### Result 1
- **Category:** Dashboard
- **Guideline:** Use UDashboardSidebar for navigation
- **Description:** Provides collapsible resizable sidebar with mobile support
- **Do:** UDashboardSidebar with header default footer slots
- **Don't:** Custom sidebar implementation
- **Code Good:** <UDashboardSidebar><template #header>...</template></UDashboardSidebar>
- **Code Bad:** <aside class="w-64 border-r">
- **Severity:** Medium
- **Docs URL:** https://ui.nuxt.com/docs/components/dashboard-sidebar

### Result 2
- **Category:** Dashboard
- **Guideline:** Use UDashboardGroup for layout
- **Description:** Wraps dashboard components with sidebar state management
- **Do:** UDashboardGroup > UDashboardSidebar + UDashboardPanel
- **Don't:** Manual layout flex containers
- **Code Good:** <UDashboardGroup><UDashboardSidebar/><UDashboardPanel/></UDashboardGroup>
- **Code Bad:** <div class="flex"><aside/><main/></div>
- **Severity:** Medium
- **Docs URL:** https://ui.nuxt.com/docs/components/dashboard-group

### Result 3
- **Category:** Tables
- **Guideline:** Use UTable with data and columns props
- **Description:** Powered by TanStack Table with built-in features
- **Do:** :data and :columns props
- **Don't:** Manual table markup
- **Code Good:** <UTable :data="users" :columns="columns"/>
- **Code Bad:** <table><tr v-for="user in users">
- **Severity:** High
- **Docs URL:** https://ui.nuxt.com/docs/components/table

### Result 4
- **Category:** Loading
- **Guideline:** Use UForm loadingAuto
- **Description:** Auto-disable form during submit
- **Do:** loadingAuto on UForm (default true)
- **Don't:** Manual form disabled state
- **Code Good:** <UForm @submit="handleSubmit">
- **Code Bad:** <UForm :disabled="isSubmitting">
- **Severity:** Low
- **Docs URL:** https://ui.nuxt.com/docs/components/form

### Result 5
- **Category:** Dashboard
- **Guideline:** Use UDashboardNavbar for top navigation
- **Description:** Responsive navbar with mobile menu support
- **Do:** UDashboardNavbar in dashboard layout
- **Don't:** Custom navbar implementation
- **Code Good:** <UDashboardNavbar :links="navLinks"/>
- **Code Bad:** <nav class="border-b">
- **Severity:** Low
- **Docs URL:** https://ui.nuxt.com/docs/components/dashboard-navbar

### Result 6
- **Category:** Components
- **Guideline:** Use U prefix for components
- **Description:** All Nuxt UI components use U prefix by default
- **Do:** UButton UInput UModal
- **Don't:** Button Input Modal
- **Code Good:** <UButton>Click</UButton>
- **Code Bad:** <Button>Click</Button>
- **Severity:** Medium
- **Docs URL:** https://ui.nuxt.com/docs/getting-started/installation/nuxt

