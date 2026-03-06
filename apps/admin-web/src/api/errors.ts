export class ApiClientError extends Error {
  public readonly status: number;

  public readonly reason: string;

  public readonly correlationId?: string;

  public readonly sessionToken?: string;

  public constructor(input: {message: string; status: number; reason: string; correlationId?: string; sessionToken?: string}) {
    super(input.message);
    this.name = 'ApiClientError';
    this.status = input.status;
    this.reason = input.reason;
    this.correlationId = input.correlationId;
    this.sessionToken = input.sessionToken;
  }
}
