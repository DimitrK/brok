import {promises as fs} from 'node:fs';
import path from 'node:path';

import {describe, expect, it} from 'vitest';

type TemplatePathGroup = {
  group_id: string;
  methods: string[];
  path_patterns: string[];
  query_allowlist: string[];
  constraints?: {
    upstream_auth?: {
      type?: string;
      service?: string;
    };
  };
};

type TemplateExample = {
  allowed_hosts: string[];
  path_groups: TemplatePathGroup[];
};

const readTemplateExample = async (): Promise<TemplateExample> => {
  const templatePath = path.resolve(process.cwd(), 'assets/s3-template.example.json');
  const templateJson = await fs.readFile(templatePath, 'utf8');
  return JSON.parse(templateJson) as TemplateExample;
};

describe('s3 template example', () => {
  it('documents the typed aws_sigv4 list and object access requirements used by backup-workload', async () => {
    const template = await readTemplateExample();

    expect(template.allowed_hosts).toEqual(['backup-bucket.s3.eu-west-1.amazonaws.com']);

    const listGroup = template.path_groups.find(group => group.group_id === 'bucket-list');
    expect(listGroup).toBeDefined();
    expect(listGroup?.methods).toEqual(['GET']);
    expect(listGroup?.path_patterns).toEqual(['/']);
    expect(listGroup?.query_allowlist).toEqual(['list-type', 'prefix', 'continuation-token']);
    expect(listGroup?.constraints?.upstream_auth).toEqual({
      type: 'aws_sigv4',
      service: 's3'
    });

    const objectGroup = template.path_groups.find(group => group.group_id === 'backup-objects');
    expect(objectGroup).toBeDefined();
    expect(objectGroup?.methods).toEqual(['GET', 'PUT']);
    expect(objectGroup?.path_patterns).toEqual(['/backups/**']);
    expect(objectGroup?.query_allowlist).toEqual([]);
    expect(objectGroup?.constraints?.upstream_auth).toEqual({
      type: 'aws_sigv4',
      service: 's3'
    });
  });
});
