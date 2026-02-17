import React from 'react';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';

type AdminSignupPolicyControlsProps = {
  api: BrokerAdminApiClient;
  roles: string[];
};

export const AdminSignupPolicyControls = ({api, roles}: AdminSignupPolicyControlsProps) => {
  const isOwner = roles.includes('owner');
  const canReadPolicy = isOwner || roles.includes('admin');

  const queryClient = useQueryClient();

  const signupPolicyQuery = useQuery({
    queryKey: ['admin-signup-policy'],
    enabled: canReadPolicy,
    queryFn: ({signal}) => api.getAdminSignupPolicy(signal)
  });

  const setSignupModeMutation = useMutation({
    mutationFn: async (mode: 'allowed' | 'blocked') => api.setSignupMode({mode}),
    onSuccess: async () => {
      await queryClient.invalidateQueries({queryKey: ['admin-signup-policy']});
    }
  });

  if (!canReadPolicy) {
    return null;
  }

  const currentMode = signupPolicyQuery.data?.new_user_mode;

  return (
    <section className="signup-policy-card">
      <p className="eyebrow">Access Onboarding</p>
      <h3>Admin sign-up policy</h3>
      <p className="helper-text">
        Current mode: <strong>{currentMode ?? 'unknown'}</strong>
      </p>
      {signupPolicyQuery.data?.updated_by ? (
        <p className="helper-text">
          Last updated by {signupPolicyQuery.data.updated_by} at {signupPolicyQuery.data.updated_at}
        </p>
      ) : null}

      {isOwner ? (
        <div className="policy-actions">
          <button
            type="button"
            className={`btn-secondary${currentMode === 'allowed' ? ' is-active' : ''}`}
            onClick={() => setSignupModeMutation.mutate('allowed')}
            disabled={setSignupModeMutation.isPending || currentMode === 'allowed'}
          >
            Allow new users
          </button>
          <button
            type="button"
            className={`btn-secondary${currentMode === 'blocked' ? ' is-active' : ''}`}
            onClick={() => setSignupModeMutation.mutate('blocked')}
            disabled={setSignupModeMutation.isPending || currentMode === 'blocked'}
          >
            Block new users
          </button>
        </div>
      ) : (
        <p className="helper-text">Only owner role can change sign-up mode.</p>
      )}

      <ErrorNotice error={signupPolicyQuery.error ?? setSignupModeMutation.error} />
    </section>
  );
};
