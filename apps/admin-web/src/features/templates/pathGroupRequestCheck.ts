const dataOptionNames = new Set([
  '-d',
  '--data',
  '--data-raw',
  '--data-binary',
  '--data-ascii',
  '--data-urlencode'
]);

const optionsWithValue = new Set([
  '-H',
  '--header',
  '-A',
  '--user-agent',
  '-u',
  '--user',
  '-b',
  '--cookie',
  '-e',
  '--referer',
  '--proxy',
  '-x',
  '--cert',
  '--key',
  '--cacert',
  '--connect-to',
  '--resolve'
]);

const dataOptionPrefixes = [...dataOptionNames].map(option => `${option}=`);

const normalizeMethod = (rawMethod: string | undefined, sawDataPayload: boolean) => {
  if (rawMethod?.trim()) {
    return rawMethod.trim().toUpperCase();
  }

  return sawDataPayload ? 'POST' : 'GET';
};

const defaultPortForProtocol = (protocol: string) => {
  if (protocol === 'https:') {
    return 443;
  }

  if (protocol === 'http:') {
    return 80;
  }

  return -1;
};

const tokenizeCurlInput = (input: string) => {
  const normalizedInput = input.replace(/\\\r?\n/g, ' ');

  const tokens: string[] = [];
  let currentToken = '';
  let activeQuote: "'" | '"' | undefined;
  let escaped = false;

  const pushCurrentToken = () => {
    if (!currentToken) {
      return;
    }
    tokens.push(currentToken);
    currentToken = '';
  };

  for (const character of normalizedInput) {
    if (escaped) {
      currentToken += character;
      escaped = false;
      continue;
    }

    if (activeQuote) {
      if (character === activeQuote) {
        activeQuote = undefined;
        continue;
      }

      if (activeQuote === '"' && character === '\\') {
        escaped = true;
        continue;
      }

      currentToken += character;
      continue;
    }

    if (character === "'" || character === '"') {
      activeQuote = character;
      continue;
    }

    if (character === '\\') {
      escaped = true;
      continue;
    }

    if (/\s/.test(character)) {
      pushCurrentToken();
      continue;
    }

    currentToken += character;
  }

  if (escaped) {
    currentToken += '\\';
  }

  if (activeQuote) {
    throw new Error('Unable to parse cURL input because a quote is not closed.');
  }

  pushCurrentToken();
  return tokens;
};

const parseCurlOptions = (tokens: string[]) => {
  const commandTokens = tokens[0] === 'curl' ? tokens.slice(1) : [...tokens];

  let method: string | undefined;
  let requestUrl: string | undefined;
  let sawDataPayload = false;

  for (let index = 0; index < commandTokens.length; index += 1) {
    const token = commandTokens[index] ?? '';
    const nextToken = commandTokens[index + 1];

    if (token === '-X' || token === '--request') {
      if (nextToken) {
        method = nextToken;
        index += 1;
      }
      continue;
    }

    if (token.startsWith('--request=')) {
      method = token.slice('--request='.length);
      continue;
    }

    if (token === '--url') {
      if (nextToken) {
        requestUrl = nextToken;
        index += 1;
      }
      continue;
    }

    if (token.startsWith('--url=')) {
      requestUrl = token.slice('--url='.length);
      continue;
    }

    if (dataOptionNames.has(token)) {
      sawDataPayload = true;
      if (nextToken) {
        index += 1;
      }
      continue;
    }

    if (dataOptionPrefixes.some(prefix => token.startsWith(prefix))) {
      sawDataPayload = true;
      continue;
    }

    if (optionsWithValue.has(token) && nextToken) {
      index += 1;
      continue;
    }

    if (!token.startsWith('-') && /^https?:\/\//i.test(token) && !requestUrl) {
      requestUrl = token;
    }
  }

  if (!requestUrl) {
    throw new Error('Unable to parse cURL input because a request URL is missing.');
  }

  return {
    method: normalizeMethod(method, sawDataPayload),
    requestUrl
  };
};

export type ParsedCurlRequest = {
  method: string;
  url: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
};

export const parseCurlRequest = (input: string): ParsedCurlRequest => {
  const tokens = tokenizeCurlInput(input);
  const parsedOptions = parseCurlOptions(tokens);

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(parsedOptions.requestUrl);
  } catch {
    throw new Error('Unable to parse cURL input because the URL is invalid.');
  }

  return {
    method: parsedOptions.method,
    url: parsedUrl.toString(),
    scheme: parsedUrl.protocol.slice(0, -1).toLowerCase(),
    host: parsedUrl.hostname.toLowerCase(),
    port: parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : defaultPortForProtocol(parsedUrl.protocol),
    path: parsedUrl.pathname || '/'
  };
};

export type PathGroupRequestCheck = {
  request: ParsedCurlRequest;
  hostMatched: boolean;
  schemeMatched: boolean;
  portMatched: boolean;
  methodMatched: boolean;
  pathMatched: boolean;
  pathMatchState: 'matched' | 'not_matched' | 'invalid_pattern';
  matchedPattern?: string;
  invalidPatterns: string[];
  matched: boolean;
  reason: string;
};

const evaluatePathGroupRequest = (input: {
  request: ParsedCurlRequest;
  allowedHosts: string[];
  methods: string[];
  pathPatterns: string[];
}): PathGroupRequestCheck => {
  const normalizedAllowedHosts = input.allowedHosts.map(host => host.trim().toLowerCase()).filter(Boolean);
  const normalizedMethods = input.methods.map(method => method.trim().toUpperCase()).filter(Boolean);
  const normalizedPatterns = input.pathPatterns.map(pattern => pattern.trim()).filter(Boolean);

  const hostMatched = normalizedAllowedHosts.length > 0 && normalizedAllowedHosts.includes(input.request.host);
  const schemeMatched = input.request.scheme === 'https';
  const portMatched = input.request.port === 443;
  const methodMatched = normalizedMethods.includes(input.request.method);

  let pathMatched = false;
  let matchedPattern: string | undefined;
  const invalidPatterns: string[] = [];

  for (const pathPattern of normalizedPatterns) {
    try {
      const matcher = new RegExp(pathPattern);
      if (!pathMatched && matcher.test(input.request.path)) {
        pathMatched = true;
        matchedPattern = pathPattern;
      }
    } catch {
      invalidPatterns.push(pathPattern);
    }
  }

  const pathMatchState =
    pathMatched ? 'matched' : normalizedPatterns.length > 0 && invalidPatterns.length === normalizedPatterns.length
      ? 'invalid_pattern'
      : 'not_matched';

  const matched = hostMatched && schemeMatched && portMatched && methodMatched && pathMatched;
  const reason = matched
    ? 'Request matches this path group.'
    : !hostMatched
      ? normalizedAllowedHosts.length === 0
        ? 'No allowed hosts configured yet.'
        : `Host ${input.request.host} is not in allowed hosts.`
      : !schemeMatched
        ? `Scheme ${input.request.scheme} is not allowed (https required).`
        : !portMatched
          ? `Port ${input.request.port} is not allowed (443 required).`
          : !methodMatched
            ? `Method ${input.request.method} is not allowed by this path group.`
            : pathMatchState === 'invalid_pattern'
              ? 'Path regex validation failed because all configured patterns are invalid.'
              : `Path ${input.request.path} did not match this path group regex set.`;

  return {
    request: input.request,
    hostMatched,
    schemeMatched,
    portMatched,
    methodMatched,
    pathMatched,
    pathMatchState,
    ...(matchedPattern ? {matchedPattern} : {}),
    invalidPatterns,
    matched,
    reason
  };
};

export const checkPathGroupCurlRequest = (input: {
  curl: string;
  allowedHosts: string[];
  methods: string[];
  pathPatterns: string[];
}): PathGroupRequestCheck => {
  const request = parseCurlRequest(input.curl);

  return evaluatePathGroupRequest({
    request,
    allowedHosts: input.allowedHosts,
    methods: input.methods,
    pathPatterns: input.pathPatterns
  });
};

export type TemplatePathGroupRequestCheck = {
  groupId: string;
  check: PathGroupRequestCheck;
};

export type TemplateRequestCheck = {
  request: ParsedCurlRequest;
  hostMatched: boolean;
  schemeMatched: boolean;
  portMatched: boolean;
  matched: boolean;
  matchedPathGroups: TemplatePathGroupRequestCheck[];
  failedPathGroups: TemplatePathGroupRequestCheck[];
  reason: string;
};

export const checkTemplateCurlRequest = (input: {
  curl: string;
  allowedHosts: string[];
  pathGroups: Array<{
    groupId: string;
    methods: string[];
    pathPatterns: string[];
  }>;
}): TemplateRequestCheck => {
  const request = parseCurlRequest(input.curl);

  const checksByPathGroup = input.pathGroups.map<TemplatePathGroupRequestCheck>(pathGroup => ({
    groupId: pathGroup.groupId,
    check: evaluatePathGroupRequest({
      request,
      allowedHosts: input.allowedHosts,
      methods: pathGroup.methods,
      pathPatterns: pathGroup.pathPatterns
    })
  }));

  const matchedPathGroups = checksByPathGroup.filter(pathGroup => pathGroup.check.matched);
  const failedPathGroups = checksByPathGroup.filter(pathGroup => !pathGroup.check.matched);

  const hostMatched = checksByPathGroup.every(pathGroup => pathGroup.check.hostMatched);
  const schemeMatched = checksByPathGroup.every(pathGroup => pathGroup.check.schemeMatched);
  const portMatched = checksByPathGroup.every(pathGroup => pathGroup.check.portMatched);
  const matched = matchedPathGroups.length > 0;

  const reason = matched
    ? `Request matches template via path group ${matchedPathGroups.map(pathGroup => pathGroup.groupId).join(', ')}.`
    : !hostMatched
      ? `Host ${request.host} is not in template allowed hosts.`
      : !schemeMatched
        ? `Scheme ${request.scheme} is not allowed (https required).`
        : !portMatched
          ? `Port ${request.port} is not allowed (443 required).`
          : 'No path group matched this request.';

  return {
    request,
    hostMatched,
    schemeMatched,
    portMatched,
    matched,
    matchedPathGroups,
    failedPathGroups,
    reason
  };
};
