export const TEMPLATE_ID_PREFIX = 'tpl_';

export const toCsvList = (value: string) =>
  value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

export const toLineList = (value: string) =>
  value
    .split('\n')
    .map(item => item.trim())
    .filter(Boolean);

export const normalizeTemplateIdSuffix = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');

export const splitTemplateId = (value: string) => {
  const normalized = value.trim().toLowerCase();
  if (!normalized.startsWith(TEMPLATE_ID_PREFIX)) {
    return normalizeTemplateIdSuffix(normalized);
  }

  return normalizeTemplateIdSuffix(normalized.slice(TEMPLATE_ID_PREFIX.length));
};

export const buildTemplateId = (suffix: string) => `${TEMPLATE_ID_PREFIX}${normalizeTemplateIdSuffix(suffix)}`;
