import axios, { type AxiosInstance } from "axios";
import { handleApiError } from "./errors.js";

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;

const shodanApi: AxiosInstance = axios.create({
  baseURL: "https://api.shodan.io",
  timeout: 30000,
});

const exploitsApi: AxiosInstance = axios.create({
  baseURL: "https://exploits.shodan.io/api",
  timeout: 30000,
});

const cvedbApi: AxiosInstance = axios.create({
  baseURL: "https://cvedb.shodan.io/api",
  timeout: 30000,
});

function requireApiKey(): string {
  if (!SHODAN_API_KEY) {
    throw new Error(
      "SHODAN_API_KEY environment variable is not set. Get your API key from https://account.shodan.io/",
    );
  }
  return SHODAN_API_KEY;
}

export async function shodanRequest(
  endpoint: string,
  params: Record<string, unknown> = {},
  method: "GET" | "POST" | "DELETE" = "GET",
): Promise<unknown> {
  const key = requireApiKey();
  const requestParams = { ...params, key };

  try {
    let response;
    if (method === "POST") {
      response = await shodanApi.post(endpoint, null, {
        params: requestParams,
      });
    } else if (method === "DELETE") {
      response = await shodanApi.delete(endpoint, { params: requestParams });
    } else {
      response = await shodanApi.get(endpoint, { params: requestParams });
    }
    return response.data;
  } catch (error) {
    handleApiError(error, endpoint);
  }
}

export async function exploitsRequest(
  endpoint: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const key = requireApiKey();
  const requestParams = { ...params, key };

  try {
    const response = await exploitsApi.get(endpoint, { params: requestParams });
    return response.data;
  } catch (error) {
    handleApiError(error, endpoint);
  }
}

export async function cvedbRequest(
  endpoint: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  try {
    const response = await cvedbApi.get(endpoint, { params });
    return response.data;
  } catch (error) {
    handleApiError(error, endpoint);
  }
}
