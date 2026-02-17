import {z} from 'zod';

const envSchema = z
  .object({
    VITE_BROKER_ADMIN_API_BASE_URL: z.string().url().optional()
  })
  .strict();

const rawBaseUrl = (import.meta as {env: Record<string, unknown>}).env.VITE_BROKER_ADMIN_API_BASE_URL;
const parsedEnv = envSchema.parse({
  VITE_BROKER_ADMIN_API_BASE_URL: typeof rawBaseUrl === 'string' ? rawBaseUrl : undefined
});

export const appConfig = {
  apiBaseUrl: parsedEnv.VITE_BROKER_ADMIN_API_BASE_URL ?? 'http://localhost:8080'
} as const;
