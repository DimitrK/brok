import React from 'react';
type JsonEditorProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  rows?: number;
};

export const JsonEditor = ({label, value, onChange, rows = 10}: JsonEditorProps) => (
  <label className="field">
    <span>{label}</span>
    <textarea
      className="json-input"
      rows={rows}
      value={value}
      onChange={event => onChange(event.currentTarget.value)}
      spellCheck={false}
    />
  </label>
);
