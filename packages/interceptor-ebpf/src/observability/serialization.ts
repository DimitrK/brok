import {
  parseControlPlaneAuthzEvent,
  parseDataplanePacketEvent,
  type ControlPlaneAuthzEvent,
  type DataplanePacketEvent
} from '../contracts/events.js';

export type DataplaneLogRecord = {
  code_namespace: 'dataplane_verdict';
  reason_code: DataplanePacketEvent['reason_code'];
  verdict: DataplanePacketEvent['verdict'];
  would_block?: DataplanePacketEvent['would_block'];
  hook?: DataplanePacketEvent['hook'];
  cgroup_id?: DataplanePacketEvent['cgroup_id'];
  message?: DataplanePacketEvent['message'];
};

export type ControlAuthzLogRecord = {
  code_namespace: 'control_authz';
  reason_code: ControlPlaneAuthzEvent['reason_code'];
  message: ControlPlaneAuthzEvent['message'];
  command?: ControlPlaneAuthzEvent['command'];
};

export function serializeDataplanePacketEventToLog(eventInput: unknown): DataplaneLogRecord {
  const event = parseDataplanePacketEvent(eventInput);

  return {
    code_namespace: event.code_namespace,
    reason_code: event.reason_code,
    verdict: event.verdict,
    ...(event.would_block !== undefined ? {would_block: event.would_block} : {}),
    ...(event.hook ? {hook: event.hook} : {}),
    ...(event.cgroup_id ? {cgroup_id: event.cgroup_id} : {}),
    ...(event.message ? {message: event.message} : {})
  };
}

export function serializeControlPlaneAuthzErrorToLog(eventInput: unknown): ControlAuthzLogRecord {
  const event = parseControlPlaneAuthzEvent(eventInput);

  return {
    code_namespace: event.code_namespace,
    reason_code: event.reason_code,
    message: event.message,
    ...(event.command ? {command: event.command} : {})
  };
}
