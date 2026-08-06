# Palette's Journal - Critical Learnings Only

## 2025-02-15 - [Keyboard Navigation Moat in Custom Sidebar Elements]
**Learning:** Custom UI frameworks often use `div` elements for sidebar/navigation menus. While CSS styling can make these elements look identical to links/buttons, they are completely invisible to screen readers and keyboard-only users who rely on tabIndex, appropriate roles (`role="tab"`), and state properties (`aria-selected`). Adding `tabindex="0"`, standard ARIA roles, toggling `aria-selected` dynamically, and listening for `Enter`/`Space` keydown events restores complete functional keyboard parity.
**Action:** When working on custom navigation or interactive controls, always inspect semantic markup and keyboard navigation capabilities, implementing proper ARIA semantics and focus indicators.

## 2025-02-18 - [WAI-ARIA Accessibility and Keyboard Trapping in Vanilla HTML Modals]
**Learning:** Generic modals implemented using absolute overlays are often neglected by keyboard focus and screen-reader systems. By adding appropriate attributes (`role="dialog"`, `aria-modal="true"`, `aria-labelledby="modalTitle"`), keeping track of the `document.activeElement` that triggered the modal, trapping focus inside the modal dynamically (on both `Tab` and `Shift + Tab`), and implementing `Escape` key listeners to dismiss the modal, vanilla HTML modals achieve full WCAG-compliant keyboard accessibility and user-friendly UX.
**Action:** When implementing or modifying modal overlays, always ensure standard WAI-ARIA definitions, set initial focus on opening, trap keyboard navigation, and cleanly restore focus to the triggering element upon closure.

## 2025-02-21 - [Semantic Refactoring of Custom Close and Dismiss Badges]
**Learning:** Vanilla HTML UIs often implement close, delete, or remove actions as clickable `span` elements (e.g., custom × or ✕ characters) to simplify design. While visually acceptable, these are completely invisible to screen readers and keyboard users. Replacing them with native `<button type="button">` elements styled with custom reset styling (`background:none; border:none; outline:none; padding:0; cursor:pointer; font-family:inherit;`) preserves visual layout perfectly while natively restoring keyboard navigation focus, ARIA role mapping, and keyboard activation behavior without requiring complex event handlers.
**Action:** When working on icon-only or custom interactive close badges, always replace `span` elements with native, reset-styled `button` elements, and supply matching `aria-label` and `title` attributes.
