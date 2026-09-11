// Where the bytes come from, and why they sometimes do not arrive.
//
// Two jobs, both of them about being specific. Read a URL and say what format
// it looks like -- including the two formats this crate cannot read yet, so
// they get a named answer instead of a parse failure. And when a fetch goes
// wrong, say which of the three ways it went wrong, because "failed to fetch"
// is the least useful sentence a browser says.

export const SAMPLES = 'samples';

export const FORMATS = [
  {
    id: 'parquet',
    name: 'Parquet',
    end: 'suffix',
    extensions: ['.parquet', '.pq', '.parq'],
  },
  {
    id: 'cog',
    name: 'Cloud-optimized GeoTIFF',
    end: 'prefix',
    extensions: ['.tif', '.tiff', '.gtiff', '.gtif'],
  },
];

export const formatName = (id) => FORMATS.find((f) => f.id === id)?.name || id;

/**
 * The two formats with a resolver still to be written.
 *
 * Detecting these from the URL is the whole point: a Zarr store handed to the
 * Parquet resolver fails with "no magic bytes", which tells the reader nothing
 * about why. A named answer with the issue behind it does.
 */
export const NOT_YET = {
  zarr: {
    name: 'Zarr',
    issue: 'https://github.com/alukach/cloud-native-access-control-poc/issues/1',
    why:
      'Zarr has no resolver yet. A Zarr store is a key prefix rather than one object, '
      + 'so its unit of access is a whole chunk object and the policy question moves from '
      + '"which byte range" to "which key" -- a different shape of index from the two here.',
  },
  icechunk: {
    name: 'Icechunk',
    issue: 'https://github.com/alukach/cloud-native-access-control-poc/issues/3',
    why:
      'Icechunk has no resolver yet. Its manifests indirect from an array region to the '
      + 'chunk objects holding it, so a range on a manifest and a range on a chunk are two '
      + 'different authorization questions and the index has to carry both.',
  },
};

/** Files that only ever appear inside a Zarr store. */
const ZARR_FILES = ['zarr.json', '.zarray', '.zgroup', '.zattrs', '.zmetadata'];
/** The directories an Icechunk repository roots itself with. */
const ICECHUNK_DIRS = ['snapshots', 'manifests', 'transactions'];

/**
 * Path segments, decoded one at a time.
 *
 * Decoding the whole path first would turn a `%2F` inside one segment into a
 * separator and invent a directory that is not there -- which is not
 * hypothetical: Hugging Face serves Parquet from a `refs%2Fconvert%2Fparquet`
 * revision, and a whole-path decode reads a `refs` directory out of it.
 */
const pathSegments = (url) =>
  url.pathname.split('/').filter(Boolean).map((segment) => {
    try {
      return decodeURIComponent(segment).toLowerCase();
    } catch {
      return segment.toLowerCase();
    }
  });

/** `refs/branch.main`, the one shape an Icechunk `refs` directory takes. */
function hasIcechunkRef(segments) {
  const at = segments.indexOf('refs');
  const next = at >= 0 ? segments[at + 1] : undefined;
  return Boolean(next && (next.startsWith('branch.') || next.startsWith('tag.')));
}

/**
 * What is at the other end of this URL, judged from the URL alone.
 *
 * Returns one of: `{error}` for something that is not a fetchable URL,
 * `{notYet}` for a format named in [`NOT_YET`], `{format, from}` for a
 * recognised extension, or `{format: null, hint}` when the extension settles
 * nothing and the user has to say.
 */
export function detect(raw) {
  const text = String(raw || '').trim();
  if (!text) return { format: null, hint: 'Paste a URL.' };

  let url;
  try {
    url = new URL(text, location.href);
  } catch {
    return { error: 'That is not a URL.' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: `Only http and https are fetched; this is ${url.protocol}` };
  }

  const segments = pathSegments(url);
  const last = segments[segments.length - 1] || '';

  // The object's own name first. A name that says what the object is beats any
  // guess from the directories above it -- those belong to the service, not to
  // the file.
  if (ZARR_FILES.includes(last) || last.endsWith('.zarr')) {
    return { notYet: 'zarr', from: `the name "${last}"` };
  }
  if (last.endsWith('.icechunk')) return { notYet: 'icechunk', from: `the name "${last}"` };

  for (const format of FORMATS) {
    const ext = format.extensions.find((e) => last.endsWith(e));
    if (ext) return { format: format.id, from: `the ${ext} extension`, url: url.href };
  }

  // Then the layout around it, which is all there is to go on for a chunk key.
  if (segments.some((s) => s.endsWith('.zarr'))) {
    return { notYet: 'zarr', from: 'the .zarr store in this path' };
  }
  if (
    segments.includes('icechunk')
    || ICECHUNK_DIRS.some((d) => segments.includes(d))
    || hasIcechunkRef(segments)
  ) {
    return { notYet: 'icechunk', from: 'the Icechunk repository layout in this path' };
  }

  // No extension and a trailing slash is a key prefix, which is what both of
  // the unimplemented formats look like. Say so rather than guessing.
  if (url.pathname.endsWith('/') || !last.includes('.')) {
    return {
      format: null,
      prefix: true,
      hint:
        'This looks like a key prefix rather than a single object. Zarr and Icechunk stores '
        + 'are prefixes, and neither has a resolver yet. If it really is one Parquet or '
        + 'GeoTIFF object, choose the format below.',
    };
  }
  return {
    format: null,
    hint: `Nothing recognisable in "${last}". Choose the format below.`,
  };
}

// ---- Failures ------------------------------------------------------------

/**
 * A fetch that went wrong in a way worth naming.
 *
 * `kind` is one of `cors`, `http`, `range-ignored` or `opaque`. The page
 * renders each differently, because they are four different things to fix and
 * a single "could not load the file" hides which.
 */
export class SourceError extends Error {
  constructor(kind, message, detail = '') {
    super(message);
    this.name = 'SourceError';
    this.kind = kind;
    this.detail = detail;
  }
}

const CORS_DETAIL =
  'The fetch threw before any status arrived. A browser reports a CORS refusal and an address '
  + 'nothing answers on identically — no status, no headers, no body — so check that the host is '
  + 'reachable, and then that it opts in. A cross-origin ranged read needs three things: an '
  + 'Access-Control-Allow-Origin covering this page; an answer to the OPTIONS preflight with '
  + 'Access-Control-Allow-Headers: Range, because Range is not a safelisted request header; '
  + 'and Access-Control-Expose-Headers: Content-Range, without which the reply is opaque to '
  + 'the checks below. Most S3 buckets send none of them. Nothing on this page can work '
  + 'around it -- the refusal happens in the browser, before the response reaches any script.';

/** `fetch` itself threw: no status, no headers, no body. That means CORS. */
export const corsError = (url, cause) =>
  new SourceError(
    'cors',
    `The browser refused to hand this page the response from ${new URL(url, location.href).host}.`,
    `${CORS_DETAIL}${cause ? `\n\nThe browser said: ${cause}` : ''}`,
  );

export const httpError = (url, status, statusText) =>
  new SourceError(
    'http',
    `${status} ${statusText || ''} from ${new URL(url, location.href).host}`.trim(),
    status === 403
      ? 'A private object, a requester-pays bucket, or an expired signature. The request got '
        + 'through -- the host answered it and said no.'
      : status === 404
        ? 'The host answered, and there is nothing at that path. Check the key.'
        : 'The host answered with an error. Nothing was read.',
  );

/**
 * The interesting one.
 *
 * RFC 9110 §14.2: a server that does not understand a Range header must ignore
 * it and return the entire representation. That is correct HTTP, and it is the
 * reason this whole project exists -- it is also, exactly, what makes the demo
 * unable to continue.
 */
export const rangeIgnoredError = (url, asked, got) =>
  new SourceError(
    'range-ignored',
    `${new URL(url, location.href).host} ignored the Range header and sent the whole object.`,
    `Asked for ${asked} bytes and got 200 with ${got.toLocaleString()}. RFC 9110 §14.2 says a `
      + 'server that does not understand a Range header must ignore it and return the entire '
      + 'representation, so this host is behaving correctly -- it simply does not do ranges. '
      + 'The demo stops here, and the reason is the point of it: the bytes that arrived are '
      + 'not the bytes that were asked for, so a decision made about the requested range '
      + 'authorized nothing that was actually served. Range support is not a nicety on top of '
      + 'cloud-native formats; it is the seam every one of them is built on. '
      + '(python3 -m http.server does this. So does any static handler that never learned §14.2.)',
  );

export const opaqueError = (url) =>
  new SourceError(
    'opaque',
    `${new URL(url, location.href).host} allows this origin but hides the headers that prove a range was served.`,
    'The response came back, but neither a Content-Length from HEAD nor a Content-Range from '
      + 'the ranged GET is readable, so the object size is unknown. Add '
      + 'Access-Control-Expose-Headers: Content-Range to the bucket CORS rule.',
  );

/**
 * Public objects that really do serve CORS and ranges.
 *
 * Verified with an OPTIONS preflight carrying `Access-Control-Request-Headers:
 * range` and a `bytes=0-99` GET, not assumed. Most public buckets fail one or
 * both; these two are here because they passed.
 */
export const EXAMPLES = [
  {
    name: 'Sentinel-2 L2A · B01',
    format: 'cog',
    url: 'https://sentinel-cogs.s3.us-west-2.amazonaws.com/sentinel-s2-l2a-cogs/1/C/CV/2018/10/S2B_1CCV_20181004_0_L2A/B01.tif',
    note: '1.4 MB COG on the AWS Open Data registry. Answers the preflight with Access-Control-Allow-Headers: Range and serves 206.',
  },
  {
    name: 'Adult census income',
    format: 'parquet',
    url: 'https://huggingface.co/datasets/scikit-learn/adult-census-income/resolve/refs%2Fconvert%2Fparquet/default/train/0000.parquet',
    note: '540 kB of Parquet on Hugging Face: 15 columns, 33 row groups. It redirects, and the redirect target answers the preflight too, which is the part most hosts get wrong. Hugging Face is not a quick origin and boundary-aligned issues 134 ranges against it, so give it a minute.',
  },
  {
    name: 'hyperparam · bunnies',
    format: 'parquet',
    url: 'https://hyperparam-public.s3.amazonaws.com/bunnies.parquet',
    note: '2.1 kB, which is smaller than hyparquet\'s own first read. The reader asks for the whole object in one range, so there is no seam to decide anything at — the shortest demonstration on this page of why object size is what makes range-level policy mean something.',
  },
];
