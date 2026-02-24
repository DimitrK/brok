import type {OpenApiTemplate} from '@broker-interceptor/schemas';

const toSortedUnique = (values: string[]) => [...new Set(values)].sort((left, right) => left.localeCompare(right));

const formatList = (values: string[]) => values.join(', ');

const diffList = (previousValues: string[], currentValues: string[]) => {
  const previous = new Set(previousValues);
  const current = new Set(currentValues);

  const added = [...current].filter(value => !previous.has(value)).sort((left, right) => left.localeCompare(right));
  const removed = [...previous]
    .filter(value => !current.has(value))
    .sort((left, right) => left.localeCompare(right));

  return {added, removed};
};

export const buildTemplateVersionIndex = (templates: OpenApiTemplate[]) => {
  const index = new Map<string, OpenApiTemplate[]>();

  for (const template of templates) {
    const history = index.get(template.template_id) ?? [];
    history.push(template);
    index.set(template.template_id, history);
  }

  for (const [templateId, history] of index.entries()) {
    index.set(
      templateId,
      [...history].sort((left, right) => right.version - left.version)
    );
  }

  return index;
};

export const getLatestTemplateVersions = (templateVersionIndex: Map<string, OpenApiTemplate[]>) =>
  [...templateVersionIndex.values()]
    .map(history => history[0])
    .filter((template): template is OpenApiTemplate => Boolean(template))
    .sort((left, right) => left.template_id.localeCompare(right.template_id));

export const summarizeTemplateVersionDiff = (previous: OpenApiTemplate, current: OpenApiTemplate) => {
  const summary: string[] = [];

  if (previous.provider !== current.provider) {
    summary.push(`Provider changed: ${previous.provider} -> ${current.provider}`);
  }

  if ((previous.description ?? '') !== (current.description ?? '')) {
    summary.push(
      `Description changed: "${previous.description ?? ''}" -> "${current.description ?? ''}"`
    );
  }

  const hostDiff = diffList(toSortedUnique(previous.allowed_hosts), toSortedUnique(current.allowed_hosts));
  if (hostDiff.added.length > 0 || hostDiff.removed.length > 0) {
    summary.push(
      `Allowed hosts: +[${formatList(hostDiff.added)}] -[${formatList(hostDiff.removed)}]`
    );
  }

  const previousPathGroups = new Map(previous.path_groups.map(pathGroup => [pathGroup.group_id, pathGroup]));
  const currentPathGroups = new Map(current.path_groups.map(pathGroup => [pathGroup.group_id, pathGroup]));

  const previousGroupIds = new Set(previousPathGroups.keys());
  const currentGroupIds = new Set(currentPathGroups.keys());

  const addedGroups = [...currentGroupIds]
    .filter(groupId => !previousGroupIds.has(groupId))
    .sort((left, right) => left.localeCompare(right));
  const removedGroups = [...previousGroupIds]
    .filter(groupId => !currentGroupIds.has(groupId))
    .sort((left, right) => left.localeCompare(right));

  if (addedGroups.length > 0) {
    summary.push(`Path groups added: ${formatList(addedGroups)}`);
  }

  if (removedGroups.length > 0) {
    summary.push(`Path groups removed: ${formatList(removedGroups)}`);
  }

  const sharedGroups = [...currentGroupIds]
    .filter(groupId => previousGroupIds.has(groupId))
    .sort((left, right) => left.localeCompare(right));

  for (const groupId of sharedGroups) {
    const previousPathGroup = previousPathGroups.get(groupId);
    const currentPathGroup = currentPathGroups.get(groupId);
    if (!previousPathGroup || !currentPathGroup) {
      continue;
    }

    if (previousPathGroup.risk_tier !== currentPathGroup.risk_tier) {
      summary.push(
        `Path group ${groupId} risk tier changed: ${previousPathGroup.risk_tier} -> ${currentPathGroup.risk_tier}`
      );
    }

    if (previousPathGroup.approval_mode !== currentPathGroup.approval_mode) {
      summary.push(
        `Path group ${groupId} approval mode changed: ${previousPathGroup.approval_mode} -> ${currentPathGroup.approval_mode}`
      );
    }

    const methodDiff = diffList(
      toSortedUnique(previousPathGroup.methods),
      toSortedUnique(currentPathGroup.methods)
    );
    if (methodDiff.added.length > 0 || methodDiff.removed.length > 0) {
      summary.push(
        `Path group ${groupId} methods: +[${formatList(methodDiff.added)}] -[${formatList(methodDiff.removed)}]`
      );
    }

    const patternDiff = diffList(
      toSortedUnique(previousPathGroup.path_patterns),
      toSortedUnique(currentPathGroup.path_patterns)
    );
    if (patternDiff.added.length > 0 || patternDiff.removed.length > 0) {
      summary.push(
        `Path group ${groupId} path patterns: +[${formatList(patternDiff.added)}] -[${formatList(patternDiff.removed)}]`
      );
    }

    const queryDiff = diffList(
      toSortedUnique(previousPathGroup.query_allowlist),
      toSortedUnique(currentPathGroup.query_allowlist)
    );
    if (queryDiff.added.length > 0 || queryDiff.removed.length > 0) {
      summary.push(
        `Path group ${groupId} query allowlist: +[${formatList(queryDiff.added)}] -[${formatList(queryDiff.removed)}]`
      );
    }

    const headerDiff = diffList(
      toSortedUnique(previousPathGroup.header_forward_allowlist),
      toSortedUnique(currentPathGroup.header_forward_allowlist)
    );
    if (headerDiff.added.length > 0 || headerDiff.removed.length > 0) {
      summary.push(
        `Path group ${groupId} header allowlist: +[${formatList(headerDiff.added)}] -[${formatList(headerDiff.removed)}]`
      );
    }

    if (previousPathGroup.body_policy.max_bytes !== currentPathGroup.body_policy.max_bytes) {
      summary.push(
        `Path group ${groupId} max body bytes changed: ${previousPathGroup.body_policy.max_bytes} -> ${currentPathGroup.body_policy.max_bytes}`
      );
    }

    const contentTypeDiff = diffList(
      toSortedUnique(previousPathGroup.body_policy.content_types),
      toSortedUnique(currentPathGroup.body_policy.content_types)
    );
    if (contentTypeDiff.added.length > 0 || contentTypeDiff.removed.length > 0) {
      summary.push(
        `Path group ${groupId} content types: +[${formatList(contentTypeDiff.added)}] -[${formatList(contentTypeDiff.removed)}]`
      );
    }
  }

  return summary.length > 0 ? summary : ['No contract changes detected between these versions.'];
};
