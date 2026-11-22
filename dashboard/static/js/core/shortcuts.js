/**
 * Engine de scurtaturi de tastatura pentru operare rapida SOC fara mouse.
 *   /         -> focus pe bara DSL Query
 *   Ctrl+K    -> Command Palette
 *   1 .. 7    -> schimbare rapida de modul (Overview .. Defense)
 *   j / k     -> navigare jos / sus pe randurile tabelului activ
 *   Enter     -> deschide Split-Pane Inspector pe randul selectat
 *   Space     -> pauza / reluare polling live
 *   r         -> fortare refresh imediat
 *   Esc       -> inchide Command Palette sau Inspector
 */

import { store } from "./store.js";

const VIEW_BY_DIGIT = {
  "1": "overview",
  "2": "alerts",
  "3": "sessions",
  "4": "campaigns",
  "5": "attackers",
  "6": "killchain",
  "7": "defense",
};

function isTypingTarget(el) {
  if (!el) return false;
  const tag = (el.tagName || "").toUpperCase();
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

export function initShortcuts({ onForceRefresh, onMoveRow, onOpenSelectedRow }) {
  window.addEventListener("keydown", (ev) => {
    const key = ev.key;

    // Ctrl+K sau Cmd+K functioneaza oriunde
    if ((ev.ctrlKey || ev.metaKey) && key.toLowerCase() === "k") {
      ev.preventDefault();
      store.setPalette(!store.get().paletteOpen);
      return;
    }

    if (key === "Escape") {
      const st = store.get();
      if (st.paletteOpen) {
        ev.preventDefault();
        store.setPalette(false);
        return;
      }
      if (isTypingTarget(ev.target)) {
        ev.target.blur();
        return;
      }
      if (st.inspector.open) {
        ev.preventDefault();
        store.closeInspector();
      }
      return;
    }

    if (store.get().paletteOpen || isTypingTarget(ev.target)) {
      return;
    }

    if (key === "/") {
      ev.preventDefault();
      const input = document.getElementById("dsl-query-input");
      if (input) {
        input.focus();
        input.select();
      }
      return;
    }

    if (VIEW_BY_DIGIT[key] && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      ev.preventDefault();
      store.setView(VIEW_BY_DIGIT[key]);
      return;
    }

    if (key === " ") {
      ev.preventDefault();
      store.toggleLive();
      return;
    }

    if (key === "r" && !ev.ctrlKey && !ev.metaKey) {
      ev.preventDefault();
      if (onForceRefresh) onForceRefresh();
      return;
    }

    if (key === "j" || key === "ArrowDown") {
      if (onMoveRow && onMoveRow(1)) {
        ev.preventDefault();
      }
      return;
    }

    if (key === "k" || key === "ArrowUp") {
      if (onMoveRow && onMoveRow(-1)) {
        ev.preventDefault();
      }
      return;
    }

    if (key === "Enter") {
      if (onOpenSelectedRow && onOpenSelectedRow()) {
        ev.preventDefault();
      }
    }
  });
}
