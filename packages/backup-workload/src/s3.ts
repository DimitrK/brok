const decodeXmlEntities = (value: string) =>
  value
    .replace(/&amp;/gu, '&')
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"')
    .replace(/&#39;/gu, "'");

const buildObjectUrl = ({endpoint, key}: {endpoint: string; key: string}) =>
  `${endpoint}/${key
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/')}`;

const extractFirstTagValue = ({xml, tagName}: {xml: string; tagName: string}) => {
  const match = xml.match(new RegExp(`<${tagName}>([^<]*)</${tagName}>`, 'u'));
  return match?.[1] ? decodeXmlEntities(match[1]) : undefined;
};

export const putObject = async ({
  endpoint,
  key,
  body,
  contentType
}: {
  endpoint: string;
  key: string;
  body: Buffer | string;
  contentType: string;
}) => {
  const response = await fetch(buildObjectUrl({endpoint, key}), {
    method: 'PUT',
    headers: {
      'content-type': contentType
    },
    body
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`putObject ${key} failed with ${response.status}: ${text}`);
  }
};

export const getObject = async ({
  endpoint,
  key
}: {
  endpoint: string;
  key: string;
}) => {
  const response = await fetch(buildObjectUrl({endpoint, key}), {
    method: 'GET'
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`getObject ${key} failed with ${response.status}: ${text}`);
  }
  return Buffer.from(await response.arrayBuffer());
};

export const listManifestKeys = async ({
  endpoint,
  prefix,
  manifestFilename
}: {
  endpoint: string;
  prefix: string;
  manifestFilename: string;
}) => {
  const manifestKeys: string[] = [];
  let continuationToken: string | undefined;

  while (true) {
    const url = new URL(endpoint);
    url.searchParams.set('list-type', '2');
    url.searchParams.set('prefix', `${prefix}/`);
    if (continuationToken) {
      url.searchParams.set('continuation-token', continuationToken);
    }

    const response = await fetch(url, {method: 'GET'});
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`listObjects ${prefix} failed with ${response.status}: ${text}`);
    }
    const xml = await response.text();

    const matches = [...xml.matchAll(/<Key>([^<]+)<\/Key>/gu)];
    manifestKeys.push(
      ...matches.map(match => decodeXmlEntities(match[1] ?? '')).filter(key => key.endsWith(`/${manifestFilename}`))
    );

    const isTruncated = extractFirstTagValue({xml, tagName: 'IsTruncated'}) === 'true';
    if (!isTruncated) {
      return manifestKeys;
    }

    continuationToken = extractFirstTagValue({xml, tagName: 'NextContinuationToken'});
    if (!continuationToken) {
      throw new Error(`S3 listObjects for ${prefix} reported truncation without a continuation token`);
    }
  }
};
