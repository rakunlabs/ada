type Field = {
  name: string;
  label: string;
  type: string;
  placeholder?: string;
  required?: boolean;
};

type RegisterInfo = {
  url: string;
  fields?: Field[];
};

type StrategyDescriptor = {
  name: string;
  // The full set of kinds the server may advertise. The UI only
  // renders form / oauth / passkey explicitly; "basic", "header" and
  // "apikey" are handled by the backend transparently (no UI surface)
  // but are kept in the union so a future renderer can branch on
  // them without a type cast.
  kind: "oauth2" | "password" | "custom" | "passkey" | "basic" | "header" | "apikey";
  label: string;
  url: string;
  fields?: Field[];
  register?: RegisterInfo;
};

type AuthInfo = {
  title: string;
  subtitle?: string;
  icon?: string;
  version?: string;
  signup_first?: boolean;
  strategies: StrategyDescriptor[];
  // Theme overrides: keys are CSS variable names (bare "primary" or
  // fully-qualified "--auth-primary"); values are plain CSS values.
  theme?: Record<string, string>;
  // Optional stylesheet URL; appended to <head> on load for full restyling.
  custom_css_url?: string;
};

export type { AuthInfo, StrategyDescriptor, Field, RegisterInfo };
