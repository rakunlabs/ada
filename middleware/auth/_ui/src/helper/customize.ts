// Runtime CSS customization helpers.
//
// Theme vars arrive from /auth/info as a plain map. Keys may be written bare
// ("primary") or fully qualified ("--auth-primary") — applyThemeVars
// normalizes them to --auth-prefixed custom properties on :root.

const normalizeKey = (k: string): string => {
  const trimmed = k.trim();
  if (trimmed.startsWith("--")) return trimmed;
  if (trimmed.startsWith("auth-")) return `--${trimmed}`;
  return `--auth-${trimmed}`;
};

const applyThemeVars = (theme: Record<string, string>) => {
  const root = document.documentElement;
  for (const [key, value] of Object.entries(theme)) {
    if (value == null) continue;
    root.style.setProperty(normalizeKey(key), String(value));
  }
};

const appendCustomStylesheet = (url: string, id = "auth-custom-css") => {
  if (!url) return;
  if (document.getElementById(id)) return;

  const link = document.createElement("link");
  link.id = id;
  link.rel = "stylesheet";
  link.href = url;
  document.head.appendChild(link);
};

export { applyThemeVars, appendCustomStylesheet };
