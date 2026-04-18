class LoginError extends Error {
  status: number;
  body: Record<string, string>;

  constructor(status: number, body: Record<string, string>) {
    super(body.message || body.error || `Login failed (${status})`);
    this.status = status;
    this.body = body;
  }
}

const login = async (
  url: string,
  data: Record<string, any>,
  signal?: AbortSignal,
) => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
    signal,
  });

  if (!response.ok) {
    let body: Record<string, string> = {};
    try {
      body = await response.json();
    } catch {
      /* empty */
    }
    throw new LoginError(response.status, body);
  }

  return response.json();
};

type RegisterResult = {
  strategy?: string;
  registered?: boolean;
  auto_login?: boolean;
  redirect_path?: string;
};

const register = async (
  url: string,
  data: Record<string, any>,
  signal?: AbortSignal,
): Promise<RegisterResult> => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
    signal,
  });

  if (!response.ok) {
    let body: Record<string, string> = {};
    try {
      body = await response.json();
    } catch {
      /* empty */
    }
    throw new LoginError(response.status, body);
  }

  return response.json();
};

export { login, register, LoginError };
export type { RegisterResult };
