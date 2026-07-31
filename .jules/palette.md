# Palette's Journal - Critical Learnings Only

## 2025-02-15 - [Keyboard Navigation Moat in Custom Sidebar Elements]
**Learning:** Custom UI frameworks often use `div` elements for sidebar/navigation menus. While CSS styling can make these elements look identical to links/buttons, they are completely invisible to screen readers and keyboard-only users who rely on tabIndex, appropriate roles (`role="tab"`), and state properties (`aria-selected`). Adding `tabindex="0"`, standard ARIA roles, toggling `aria-selected` dynamically, and listening for `Enter`/`Space` keydown events restores complete functional keyboard parity.
**Action:** When working on custom navigation or interactive controls, always inspect semantic markup and keyboard navigation capabilities, implementing proper ARIA semantics and focus indicators.

## 2025-02-18 - [WAI-ARIA Accessibility and Keyboard Trapping in Vanilla HTML Modals]
**Learning:** Generic modals implemented using absolute overlays are often neglected by keyboard focus and screen-reader systems. By adding appropriate attributes (`role="dialog"`, `aria-modal="true"`, `aria-labelledby="modalTitle"`), keeping track of the `document.activeElement` that triggered the modal, trapping focus inside the modal dynamically (on both `Tab` and `Shift + Tab`), and implementing `Escape` key listeners to dismiss the modal, vanilla HTML modals achieve full WCAG-compliant keyboard accessibility and user-friendly UX.
**Action:** When implementing or modifying modal overlays, always ensure standard WAI-ARIA definitions, set initial focus on opening, trap keyboard navigation, and cleanly restore focus to the triggering element upon closure.
