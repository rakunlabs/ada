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
  kind: "oauth2" | "password" | "custom";
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
