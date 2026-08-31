# Palette's Journal - Critical Learnings Only

## 2025-02-15 - [Keyboard Navigation Moat in Custom Sidebar Elements]
**Learning:** Custom UI frameworks often use `div` elements for sidebar/navigation menus. While CSS styling can make these elements look identical to links/buttons, they are completely invisible to screen readers and keyboard-only users who rely on tabIndex, appropriate roles (`role="tab"`), and state properties (`aria-selected`). Adding `tabindex="0"`, standard ARIA roles, toggling `aria-selected` dynamically, and listening for `Enter`/`Space` keydown events restores complete functional keyboard parity.
**Action:** When working on custom navigation or interactive controls, always inspect semantic markup and keyboard navigation capabilities, implementing proper ARIA semantics and focus indicators.

## 2025-02-18 - [WAI-ARIA Accessibility and Keyboard Trapping in Vanilla HTML Modals]
**Learning:** Generic modals implemented using absolute overlays are often neglected by keyboard focus and screen-reader systems. By adding appropriate attributes (`role="dialog"`, `aria-modal="true"`, `aria-labelledby="modalTitle"`), keeping track of the `document.activeElement` that triggered the modal, trapping focus inside the modal dynamically (on both `Tab` and `Shift + Tab`), and implementing `Escape` key listeners to dismiss the modal, vanilla HTML modals achieve full WCAG-compliant keyboard accessibility and user-friendly UX.
**Action:** When implementing or modifying modal overlays, always ensure standard WAI-ARIA definitions, set initial focus on opening, trap keyboard navigation, and cleanly restore focus to the triggering element upon closure.

## 2025-02-23 - [Keyboard Accessibility and Semantic Buttons for Close Controls]
**Learning:** Clickable span and icon-only text elements used for close controls inside dynamic templates are inherently non-semantic and hidden from standard screen reader navigation. Replacing them with native HTML `<button type="button">` elements inheriting Reset styles (such as `.modal-close`) seamlessly ensures screen reader detection, tab order, and standard Enter/Space keydown handling. Furthermore, adding specific `aria-label` and `title` attributes delivers proper accessibility and desktop hover tooltips.
**Action:** When creating or modifying close icons or symbol buttons in HTML templates, always use native `<button type="button">` elements styled appropriately, and always accompany them with informative `aria-label` and `title` pairs.

## 2025-03-01 - [High-Contrast Theme-Aligned Styling for Interactive Dashboard Cues]
**Learning:** Interactive controls positioned on dark/black backgrounds suffer from severe visibility issues when using static low-contrast colors (like gray `#555`). Utilizing theme-aligned variables (`var(--text-secondary)`, `var(--accent)`) and interactive states (`hover`, `.active`, `:focus-visible`) resolves contrast ratios, ensures seamless keyboard navigation, and provides visual delight and clear affordances.
**Action:** When styling toggle or control buttons in the dashboard toolbar, define clear hover, active state variations using theme variables, and include focus ring styling for focus-visible elements.

## 2025-03-02 - [Input-Aware Global Keyboard Shortcut Guards]
**Learning:** Adding global single-key shortcuts (like `/` for search) without checking `document.activeElement` or `e.target` tag names (`INPUT`, `TEXTAREA`, `SELECT`) and `isContentEditable` properties causes keypresses inside form inputs to be intercepted, breaking basic text entry for strings containing `/` (such as GitHub repos, URLs, and scoped npm packages). Checking active element focus states ensures seamless shortcut activation without breaking input typing.
**Action:** When adding single-key global keyboard shortcuts, always guard the event handler by verifying that neither `e.target` nor `document.activeElement` is an input field or content-editable region.
