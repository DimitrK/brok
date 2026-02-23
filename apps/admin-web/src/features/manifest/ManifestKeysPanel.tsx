import React, {useMemo} from 'react';
import {useQuery} from '@tanstack/react-query';

import {BrokerAdminApiClient} from '../../api/client';
import {ErrorNotice} from '../../components/ErrorNotice';
import {Panel} from '../../components/Panel';

type ManifestPanelProps = {
  api: BrokerAdminApiClient;
};

export const ManifestPanel = ({api}: ManifestPanelProps) => {
  const manifestKeysQuery = useQuery({
    queryKey: ['manifest-keys'],
    queryFn: ({signal}) => api.listManifestKeys(signal)
  });

  const keysetJson = useMemo(() => {
    if (!manifestKeysQuery.data) {
      return undefined;
    }

    return JSON.stringify(manifestKeysQuery.data, null, 2);
  }, [manifestKeysQuery.data]);

  return (
    <Panel title="Manifest" subtitle="Inspect active signing key material distributed to interceptors.">
      <ErrorNotice error={manifestKeysQuery.error} />
      {keysetJson ? <pre className="json-view">{keysetJson}</pre> : null}
    </Panel>
  );
};
