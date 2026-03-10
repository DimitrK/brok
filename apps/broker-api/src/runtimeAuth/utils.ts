import {type OpenApiTemplate} from '@broker-interceptor/schemas';

export const resolvePathGroup = ({
  template,
  matchedPathGroupId
}: {
  template: OpenApiTemplate;
  matchedPathGroupId: string;
}) => template.path_groups.find(pathGroup => pathGroup.group_id === matchedPathGroupId) ?? null;
