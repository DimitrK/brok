/**
 * Unit tests for the broker client module.
 */

import {describe, expect, it} from 'vitest';
import {ApprovalRequiredError, RequestDeniedError} from '../broker-client.js';
import type {ExecuteResponseApprovalRequired} from '../types.js';

/**
 * Helper to create a valid summary object.
 */
function createSummary(
  overrides?: Partial<ExecuteResponseApprovalRequired['summary']>
): ExecuteResponseApprovalRequired['summary'] {
  return {
    integration_id: 'test-integration',
    action_group: 'READ',
    risk_tier: 'low',
    destination_host: 'api.example.com',
    method: 'GET',
    path: '/v1/test',
    ...overrides
  };
}

describe('ApprovalRequiredError', () => {
  it('creates error with correct properties', () => {
    const summary = createSummary({
      risk_tier: 'high',
      action_group: 'DELETE'
    });

    const error = new ApprovalRequiredError('apr_123', '2024-12-31T23:59:59Z', summary);

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('ApprovalRequiredError');
    expect(error.approvalId).toBe('apr_123');
    expect(error.expiresAt).toBe('2024-12-31T23:59:59Z');
    expect(error.summary).toEqual(summary);
  });

  it('includes approval info in message', () => {
    const summary = createSummary({
      risk_tier: 'high',
      action_group: 'DELETE'
    });

    const error = new ApprovalRequiredError('apr_abc', '2024-12-31T23:59:59Z', summary);

    expect(error.message).toContain('apr_abc');
    expect(error.message).toContain('DELETE');
    expect(error.message).toContain('high');
  });

  it('can be caught as Error', () => {
    const summary = createSummary({
      risk_tier: 'medium',
      action_group: 'UPDATE'
    });

    const error = new ApprovalRequiredError('apr_test', '2024-12-31T23:59:59Z', summary);

    expect(() => {
      throw error;
    }).toThrow(Error);

    try {
      throw error;
    } catch (e) {
      expect(e).toBeInstanceOf(ApprovalRequiredError);
    }
  });
});

describe('RequestDeniedError', () => {
  it('creates error with correct properties', () => {
    const error = new RequestDeniedError('Insufficient permissions', 'corr_123abc');

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('RequestDeniedError');
    expect(error.reason).toBe('Insufficient permissions');
    expect(error.correlationId).toBe('corr_123abc');
  });

  it('includes reason in message', () => {
    const error = new RequestDeniedError('Policy violation: resource deletion blocked', 'corr_xyz');

    expect(error.message).toContain('Policy violation');
    expect(error.message).toContain('resource deletion blocked');
  });

  it('can be caught as Error', () => {
    const error = new RequestDeniedError('Access denied', 'corr_test');

    expect(() => {
      throw error;
    }).toThrow(Error);

    try {
      throw error;
    } catch (e) {
      expect(e).toBeInstanceOf(RequestDeniedError);
    }
  });
});

describe('Error inheritance', () => {
  it('ApprovalRequiredError is instanceof Error', () => {
    const error = new ApprovalRequiredError('apr_1', '2024-01-01T00:00:00Z', createSummary());

    expect(error instanceof Error).toBe(true);
  });

  it('RequestDeniedError is instanceof Error', () => {
    const error = new RequestDeniedError('denied', 'corr_1');

    expect(error instanceof Error).toBe(true);
  });

  it('errors have stack traces', () => {
    const approvalError = new ApprovalRequiredError('apr_1', '2024-01-01T00:00:00Z', createSummary());
    const deniedError = new RequestDeniedError('denied', 'corr_1');

    expect(approvalError.stack).toBeDefined();
    expect(deniedError.stack).toBeDefined();
    expect(approvalError.stack).toContain('ApprovalRequiredError');
    expect(deniedError.stack).toContain('RequestDeniedError');
  });
});
