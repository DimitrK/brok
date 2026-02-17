import React from 'react';

type ToggleSwitchProps = {
  checked: boolean;
  onChange: (nextValue: boolean) => void;
  disabled?: boolean;
  label?: string;
  id?: string;
};

export const ToggleSwitch = ({checked, onChange, disabled = false, label, id}: ToggleSwitchProps) => (
  <button
    id={id}
    type="button"
    className={`toggle-switch${checked ? ' on' : ' off'}`}
    role="switch"
    aria-checked={checked}
    aria-label={label}
    disabled={disabled}
    onClick={event => {
      event.stopPropagation();
      onChange(!checked);
    }}
  >
    <span className="toggle-switch-track" aria-hidden>
      <span className="toggle-switch-thumb" />
    </span>
    {label ? <span className="toggle-switch-text">{label}</span> : null}
  </button>
);
