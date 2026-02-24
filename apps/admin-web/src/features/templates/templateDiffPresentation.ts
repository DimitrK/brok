type TemplateDiffPresentation =
  | {
      kind: 'list';
      label: string;
      added: string[];
      removed: string[];
    }
  | {
      kind: 'change';
      label: string;
      before: string;
      after: string;
    }
  | {
      kind: 'plain';
      text: string;
    };

const splitValues = (input: string) =>
  input
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);

export const parseTemplateDiffSummaryLine = (line: string): TemplateDiffPresentation => {
  const listDiffMatch = /^(.*?): \+\[(.*)\] -\[(.*)\]$/.exec(line);
  if (listDiffMatch) {
    return {
      kind: 'list',
      label: listDiffMatch[1],
      added: splitValues(listDiffMatch[2]),
      removed: splitValues(listDiffMatch[3])
    };
  }

  const changedMatch = /^(.*?) changed: (.*) -> (.*)$/.exec(line);
  if (changedMatch) {
    return {
      kind: 'change',
      label: changedMatch[1],
      before: changedMatch[2],
      after: changedMatch[3]
    };
  }

  const addedMatch = /^(.*?) added: (.*)$/.exec(line);
  if (addedMatch) {
    return {
      kind: 'list',
      label: addedMatch[1],
      added: splitValues(addedMatch[2]),
      removed: []
    };
  }

  const removedMatch = /^(.*?) removed: (.*)$/.exec(line);
  if (removedMatch) {
    return {
      kind: 'list',
      label: removedMatch[1],
      added: [],
      removed: splitValues(removedMatch[2])
    };
  }

  return {
    kind: 'plain',
    text: line
  };
};
