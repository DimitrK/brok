/**
 * Unit tests for the types and config schema validation.
 */

import {describe, expect, it} from 'vitest';
import {InterceptorConfigSchema, defaultLogger} from '../types.js';

describe('InterceptorConfigSchema', () => {
  describe('required fields', () => {
    it('validates valid config', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.brokerUrl).toBe('https://broker.example.com');
        expect(result.data.sessionToken).toBe('tok_abc123');
      }
    });

    it('requires brokerUrl', () => {
      const config = {
        sessionToken: 'tok_abc123'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });

    it('requires sessionToken', () => {
      const config = {
        brokerUrl: 'https://broker.example.com'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });

    it('requires brokerUrl to be a valid URL', () => {
      const config = {
        brokerUrl: 'not-a-valid-url',
        sessionToken: 'tok_abc123'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });

    it('requires sessionToken to be non-empty', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: ''
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });
  });

  describe('optional fields', () => {
    it('allows manifestPath', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        manifestPath: '/path/to/manifest.json'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.manifestPath).toBe('/path/to/manifest.json');
      }
    });

    it('allows mTLS paths', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        mtlsCertPath: '/path/to/cert.pem',
        mtlsKeyPath: '/path/to/key.pem',
        mtlsCaPath: '/path/to/ca.pem'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.mtlsCertPath).toBe('/path/to/cert.pem');
        expect(result.data.mtlsKeyPath).toBe('/path/to/key.pem');
        expect(result.data.mtlsCaPath).toBe('/path/to/ca.pem');
      }
    });
  });

  describe('defaults', () => {
    it('applies default manifestRefreshIntervalMs', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        // Default is 5 minutes
        expect(result.data.manifestRefreshIntervalMs).toBe(5 * 60 * 1000);
      }
    });

    it('applies default failOnManifestError', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123'
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.failOnManifestError).toBe(true);
      }
    });

    it('allows overriding manifestRefreshIntervalMs', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        manifestRefreshIntervalMs: 60000 // 1 minute
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.manifestRefreshIntervalMs).toBe(60000);
      }
    });

    it('allows setting failOnManifestError to false', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        failOnManifestError: false
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.failOnManifestError).toBe(false);
      }
    });
  });

  describe('manifestRefreshIntervalMs validation', () => {
    it('rejects non-positive values', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        manifestRefreshIntervalMs: 0
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });

    it('rejects negative values', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        manifestRefreshIntervalMs: -1000
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });

    it('rejects non-integer values', () => {
      const config = {
        brokerUrl: 'https://broker.example.com',
        sessionToken: 'tok_abc123',
        manifestRefreshIntervalMs: 1000.5
      };

      const result = InterceptorConfigSchema.safeParse(config);

      expect(result.success).toBe(false);
    });
  });
});

describe('defaultLogger', () => {
  it('has all required methods', () => {
    expect(typeof defaultLogger.debug).toBe('function');
    expect(typeof defaultLogger.info).toBe('function');
    expect(typeof defaultLogger.warn).toBe('function');
    expect(typeof defaultLogger.error).toBe('function');
  });

  it('does not throw when called', () => {
    expect(() => defaultLogger.debug('test')).not.toThrow();
    expect(() => defaultLogger.info('test')).not.toThrow();
    expect(() => defaultLogger.warn('test')).not.toThrow();
    expect(() => defaultLogger.error('test')).not.toThrow();
  });
});
