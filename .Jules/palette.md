# Palette's Journal - Critical UX & Accessibility Learnings

This journal is a record of critical UX/accessibility learnings discovered while working on this repository.

## 2026-07-28 - [Implicit Toggle State Desynchronization in Navigation Menus]
**Learning:** In responsive, multi-page frontend applications with sliding sidebars (e.g. mobile navigation drawers), toggling the `aria-expanded` state on the toggle button alone is insufficient. When a user clicks a menu item inside the sidebar, the application typically routes to the new page and hides the sidebar automatically (implicit close). If this navigation routing function does not synchronize the toggle button's accessibility attributes, `aria-expanded` remains `true` even though the sidebar is physically closed. This results in stale, deceptive states for assistive technologies and screen readers.
**Action:** When working on navigation menus, sidebars, or dropdowns, identify all implicit close paths (e.g., body clicks, escape key presses, or internal link clicks/routing) and ensure they explicitly update the trigger element's `aria-expanded` and visibility attributes, rather than relying solely on the direct toggle button click handler.

## 2026-07-28 - [Incomplete Tooltip & Focus State Synchronization on Input Toggle Buttons]
**Learning:** Custom inline action buttons placed inside form inputs (such as "Show/Hide" password/API key toggle buttons) are often omitted from global `:focus-visible` CSS rules and state toggle handlers. When state updates, updating `aria-label` alone leaves `title` tooltips desynchronized for mouse/hover interactions, while missing focus ring styles degrades keyboard navigation visibility.
**Action:** When creating or modifying state-toggle buttons inside input controls, ensure the toggle function updates both `aria-label` and `title` attributes in sync, and explicitly include button classes in `:focus-visible` CSS focus outline selectors.
