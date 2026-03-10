export type RuntimeAuthErrorCode =
  | 'runtime_auth_constraint_invalid'
  | 'runtime_auth_path_group_missing'
  | 'runtime_auth_secret_type_incompatible'
  | 'runtime_auth_strategy_unsupported'
  | 'runtime_auth_inputs_unavailable';

export class RuntimeAuthError extends Error {
  public readonly code: RuntimeAuthErrorCode;

  public constructor({code, message}: {code: RuntimeAuthErrorCode; message: string}) {
    super(message);
    this.name = 'RuntimeAuthError';
    this.code = code;
  }
}

export const isRuntimeAuthError = (value: unknown): value is RuntimeAuthError => value instanceof RuntimeAuthError;
