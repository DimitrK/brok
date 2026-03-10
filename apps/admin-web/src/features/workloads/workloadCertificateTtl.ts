import {z} from 'zod';

export const WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS = 30 * 24 * 60 * 60;

const workloadCertificateTtlInputSchema = z.string().trim().min(1).max(64);

type WorkloadCertificateTtlInput = z.infer<typeof workloadCertificateTtlInputSchema>;

type WorkloadCertificateTtlParseResult =
  | {
      success: true;
      seconds: number;
      displayLabel: string;
    }
  | {
      success: false;
      message: string;
    };

type WorkloadCertificateTtlParseOptions = {
  maxSeconds?: number;
};

const ttlUnitSeconds = {
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 60 * 60,
  hr: 60 * 60,
  hrs: 60 * 60,
  hour: 60 * 60,
  hours: 60 * 60,
  d: 24 * 60 * 60,
  day: 24 * 60 * 60,
  days: 24 * 60 * 60,
  mo: WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS,
  month: WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS,
  months: WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS
} as const satisfies Record<string, number>;

const describeTtl = (quantity: number, canonicalUnit: 'second' | 'minute' | 'hour' | 'day' | 'month') =>
  `${quantity} ${canonicalUnit}${quantity === 1 ? '' : 's'}`;

export const formatWorkloadCertificateTtlSeconds = (seconds: number) => {
  if (seconds % WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS === 0) {
    return describeTtl(seconds / WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS, 'month');
  }
  if (seconds % (24 * 60 * 60) === 0) {
    return describeTtl(seconds / (24 * 60 * 60), 'day');
  }
  if (seconds % (60 * 60) === 0) {
    return describeTtl(seconds / (60 * 60), 'hour');
  }
  if (seconds % 60 === 0) {
    return describeTtl(seconds / 60, 'minute');
  }

  return describeTtl(seconds, 'second');
};

const normalizeWorkloadCertificateTtlInput = (value: WorkloadCertificateTtlInput) =>
  value.trim().toLowerCase().replace(/\s+/g, ' ');

export const parseWorkloadCertificateTtlInput = (
  value: unknown,
  options: WorkloadCertificateTtlParseOptions = {}
): WorkloadCertificateTtlParseResult => {
  const parsed = workloadCertificateTtlInputSchema.safeParse(value);
  if (!parsed.success) {
    return {
      success: false,
      message: 'Enter a TTL such as `1d`, `5h`, `1 month`, or `900`.'
    };
  }

  const normalizedInput = normalizeWorkloadCertificateTtlInput(parsed.data);
  const match = /^(?<quantity>\d+)\s*(?<unit>[a-z]+)?$/.exec(normalizedInput);
  if (!match?.groups) {
    return {
      success: false,
      message: 'Use a whole number plus an optional unit like `h`, `day`, `month`, or `min`.'
    };
  }

  const quantity = Number.parseInt(match.groups.quantity, 10);
  if (!Number.isSafeInteger(quantity) || quantity < 1) {
    return {
      success: false,
      message: 'Requested TTL must be at least 1 second.'
    };
  }

  const rawUnit = match.groups.unit;
  if (!rawUnit) {
    if (options.maxSeconds !== undefined && quantity > options.maxSeconds) {
      return {
        success: false,
        message: `Requested TTL cannot exceed ${formatWorkloadCertificateTtlSeconds(options.maxSeconds)}.`
      };
    }

    return {
      success: true,
      seconds: quantity,
      displayLabel: describeTtl(quantity, 'second')
    };
  }

  const unitSeconds = ttlUnitSeconds[rawUnit as keyof typeof ttlUnitSeconds];
  if (rawUnit === 'm') {
    return {
      success: false,
      message: 'Use `min` for minutes or `mo`/`month` for months.'
    };
  }

  if (!unitSeconds) {
    return {
      success: false,
      message: 'Supported units are `s`, `min`, `h`, `d`, and `mo`/`month`.'
    };
  }

  const seconds = quantity * unitSeconds;
  if (!Number.isSafeInteger(seconds)) {
    return {
      success: false,
      message: 'Requested TTL is too large.'
    };
  }
  if (options.maxSeconds !== undefined && seconds > options.maxSeconds) {
    return {
      success: false,
      message: `Requested TTL cannot exceed ${formatWorkloadCertificateTtlSeconds(options.maxSeconds)}.`
    };
  }

  const displayLabel =
    unitSeconds === WORKLOAD_CERTIFICATE_TTL_MONTH_SECONDS
      ? describeTtl(quantity, 'month')
      : unitSeconds === 24 * 60 * 60
        ? describeTtl(quantity, 'day')
        : unitSeconds === 60 * 60
          ? describeTtl(quantity, 'hour')
          : unitSeconds === 60
            ? describeTtl(quantity, 'minute')
            : describeTtl(quantity, 'second');

  return {
    success: true,
    seconds,
    displayLabel
  };
};
