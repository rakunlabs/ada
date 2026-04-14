type Field = {
  name: string;
  label: string;
  type: string;
  placeholder?: string;
  required?: boolean;
};

type StrategyDescriptor = {
  name: string;
  kind: "oauth2" | "password" | "custom";
  label: string;
  url: string;
  fields?: Field[];
};

type AuthInfo = {
  title: string;
  subtitle?: string;
  icon?: string;
  version?: string;
  strategies: StrategyDescriptor[];
};

export type { AuthInfo, StrategyDescriptor, Field };
