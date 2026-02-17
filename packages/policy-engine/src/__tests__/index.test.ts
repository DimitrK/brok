import {describe, expect, it} from 'vitest'

import {
  DecisionReasonCodeSchema,
  appendPolicyDecisionAuditEvent,
  appendPolicyDecisionAuditEvent_INCOMPLETE,
  createPolicyEngineDbBridge,
  createPolicyEngineDbBridgeFromDbPackage,
  classifyPathGroup,
  createPolicyEngineDbBridge_INCOMPLETE,
  derivePolicyFromApprovalDecision,
  evaluatePolicyDecision,
  listPolicyRulesForDescriptorScope,
  listPolicyRulesForDescriptorScope_INCOMPLETE,
  subscribePolicyEngineInvalidation,
  validatePolicyRule
} from '../index'

describe('policy-engine exports', () => {
  it('exports core API and decision reason codes', () => {
    expect(typeof classifyPathGroup).toBe('function')
    expect(typeof evaluatePolicyDecision).toBe('function')
    expect(typeof validatePolicyRule).toBe('function')
    expect(typeof derivePolicyFromApprovalDecision).toBe('function')
    expect(typeof listPolicyRulesForDescriptorScope).toBe('function')
    expect(typeof appendPolicyDecisionAuditEvent).toBe('function')
    expect(typeof subscribePolicyEngineInvalidation).toBe('function')
    expect(typeof createPolicyEngineDbBridge).toBe('function')
    expect(typeof createPolicyEngineDbBridgeFromDbPackage).toBe('function')
    expect(typeof listPolicyRulesForDescriptorScope_INCOMPLETE).toBe('function')
    expect(typeof appendPolicyDecisionAuditEvent_INCOMPLETE).toBe('function')
    expect(typeof createPolicyEngineDbBridge_INCOMPLETE).toBe('function')
    expect(DecisionReasonCodeSchema.options).toContain('policy_default_deny')
  })
})
