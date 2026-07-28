# Palette's Journal - Critical UX & Accessibility Learnings

This journal is a record of critical UX/accessibility learnings discovered while working on this repository.

## 2026-07-28 - [Implicit Toggle State Desynchronization in Navigation Menus]
**Learning:** In responsive, multi-page frontend applications with sliding sidebars (e.g. mobile navigation drawers), toggling the `aria-expanded` state on the toggle button alone is insufficient. When a user clicks a menu item inside the sidebar, the application typically routes to the new page and hides the sidebar automatically (implicit close). If this navigation routing function does not synchronize the toggle button's accessibility attributes, `aria-expanded` remains `true` even though the sidebar is physically closed. This results in stale, deceptive states for assistive technologies and screen readers.
**Action:** When working on navigation menus, sidebars, or dropdowns, identify all implicit close paths (e.g., body clicks, escape key presses, or internal link clicks/routing) and ensure they explicitly update the trigger element's `aria-expanded` and visibility attributes, rather than relying solely on the direct toggle button click handler.
