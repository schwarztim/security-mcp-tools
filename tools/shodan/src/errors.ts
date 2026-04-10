import { UserError } from "fastmcp";

export class ShodanApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public endpoint?: string,
  ) {
    super(message);
    this.name = "ShodanApiError";
  }
}

const STATUS_MESSAGES: Record<number, string> = {
  401: "Invalid API key. Verify SHODAN_API_KEY.",
  402: "Insufficient credits. This query requires a paid Shodan plan.",
  429: "Rate limit exceeded. Wait before retrying.",
  404: "Resource not found.",
};

export function handleApiError(error: unknown, endpoint?: string): never {
  if (error instanceof ShodanApiError) {
    throw new UserError(error.message);
  }

  if (isAxiosError(error)) {
    const status = error.response?.status;
    const body = error.response?.data;
    const apiMessage = body?.error || body?.message;

    if (status && STATUS_MESSAGES[status]) {
      throw new UserError(STATUS_MESSAGES[status]);
    }

    if (apiMessage) {
      throw new UserError(`Shodan API error: ${apiMessage}`);
    }

    throw new UserError(`Shodan API error: ${error.message}`);
  }

  if (error instanceof Error) {
    throw new UserError(error.message);
  }

  throw new UserError(String(error));
}

function isAxiosError(error: unknown): error is {
  response?: { status?: number; data?: { error?: string; message?: string } };
  message: string;
} {
  return (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    ("response" in error || "isAxiosError" in error)
  );
}
