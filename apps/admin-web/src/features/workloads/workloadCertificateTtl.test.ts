import {describe, expect, it} from 'vitest';

import {
  formatWorkloadCertificateTtlSeconds,
  parseWorkloadCertificateTtlInput
} from './workloadCertificateTtl';

describe('workloadCertificateTtl', () => {
  it('parses human-friendly day and hour inputs', () => {
    expect(parseWorkloadCertificateTtlInput('1d')).toEqual({
      success: true,
      seconds: 24 * 60 * 60,
      displayLabel: '1 day'
    });
    expect(parseWorkloadCertificateTtlInput('5 hours')).toEqual({
      success: true,
      seconds: 5 * 60 * 60,
      displayLabel: '5 hours'
    });
  });

  it('parses month aliases as a 30-day TTL', () => {
    expect(parseWorkloadCertificateTtlInput('1 month')).toEqual({
      success: true,
      seconds: 30 * 24 * 60 * 60,
      displayLabel: '1 month'
    });
    expect(parseWorkloadCertificateTtlInput('1mo')).toEqual({
      success: true,
      seconds: 30 * 24 * 60 * 60,
      displayLabel: '1 month'
    });
  });

  it('accepts minute aliases and raw numeric seconds', () => {
    expect(parseWorkloadCertificateTtlInput('5min')).toEqual({
      success: true,
      seconds: 5 * 60,
      displayLabel: '5 minutes'
    });
    expect(parseWorkloadCertificateTtlInput('900')).toEqual({
      success: true,
      seconds: 900,
      displayLabel: '900 seconds'
    });
  });

  it('rejects unsupported units and malformed input', () => {
    expect(parseWorkloadCertificateTtlInput('1m')).toEqual({
      success: false,
      message: 'Use `min` for minutes or `mo`/`month` for months.'
    });
    expect(parseWorkloadCertificateTtlInput('1w')).toEqual({
      success: false,
      message: 'Supported units are `s`, `min`, `h`, `d`, and `mo`/`month`.'
    });
    expect(parseWorkloadCertificateTtlInput('abc')).toEqual({
      success: false,
      message: 'Use a whole number plus an optional unit like `h`, `day`, `month`, or `min`.'
    });
  });

  it('rejects zero and only enforces a cap when one is explicitly provided', () => {
    expect(parseWorkloadCertificateTtlInput('0')).toEqual({
      success: false,
      message: 'Requested TTL must be at least 1 second.'
    });
    expect(parseWorkloadCertificateTtlInput('31d')).toEqual({
      success: true,
      seconds: 31 * 24 * 60 * 60,
      displayLabel: '31 days'
    });
    expect(
      parseWorkloadCertificateTtlInput('31d', {
        maxSeconds: 30 * 24 * 60 * 60
      })
    ).toEqual({
      success: false,
      message: 'Requested TTL cannot exceed 1 month.'
    });
  });

  it('keeps month semantics independent from the deployment limit', () => {
    expect(
      parseWorkloadCertificateTtlInput('1mo', {
        maxSeconds: 10 * 365 * 24 * 60 * 60
      })
    ).toEqual({
      success: true,
      seconds: 30 * 24 * 60 * 60,
      displayLabel: '1 month'
    });
  });

  it('formats duration values for user-facing limit messages', () => {
    expect(formatWorkloadCertificateTtlSeconds(60)).toBe('1 minute');
    expect(formatWorkloadCertificateTtlSeconds(24 * 60 * 60)).toBe('1 day');
    expect(formatWorkloadCertificateTtlSeconds(30 * 24 * 60 * 60)).toBe('1 month');
    expect(formatWorkloadCertificateTtlSeconds(365 * 24 * 60 * 60)).toBe('365 days');
    expect(formatWorkloadCertificateTtlSeconds(90)).toBe('90 seconds');
  });
});
