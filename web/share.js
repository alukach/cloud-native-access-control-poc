// Every control on this page, in the address bar.
//
// The policy document and the principal are the long ones, so they are
// deflated before they are base64url'd: a link nobody can paste is not a
// shareable link. Each encoded value names its own encoding in its first
// character, so a link written by hand, or written before compression was
// here, still reads.

/** Raw UTF-8, base64url. Always available. */
const PLAIN = 't';
/** `deflate-raw`, base64url. Only when `CompressionStream` exists. */
const DEFLATED = 'z';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64Url(bytes) {
  let binary = '';
  // `String.fromCharCode(...bytes)` blows the argument limit on a long policy.
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text) {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function through(bytes, stream) {
  const piped = new Blob([bytes]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(piped).arrayBuffer());
}

/** Text to one query-safe token. Base64url needs no percent-encoding. */
export async function pack(text) {
  if (!text) return '';
  const raw = encoder.encode(text);
  if (typeof CompressionStream === 'function') {
    try {
      const squeezed = await through(raw, new CompressionStream('deflate-raw'));
      // Short strings come out longer deflated. Take whichever wins.
      if (squeezed.length < raw.length) return DEFLATED + toBase64Url(squeezed);
    } catch {
      // An engine that has the constructor but not `deflate-raw`. Fall through.
    }
  }
  return PLAIN + toBase64Url(raw);
}

/**
 * A token back to text.
 *
 * Anything that does not decode is returned as it arrived rather than thrown.
 * A query parameter is untrusted input, and a policy that arrives as rubbish
 * has to reach the editor and fail the same validation a typed one would --
 * an inline diagnostic, not an exception on page load.
 */
export async function unpack(value) {
  if (!value) return '';
  const body = value.slice(1);
  try {
    if (value[0] === DEFLATED) {
      return decoder.decode(await through(fromBase64Url(body), new DecompressionStream('deflate-raw')));
    }
    if (value[0] === PLAIN) return decoder.decode(fromBase64Url(body));
  } catch {
    return value;
  }
  // No tag: a hand-written link, or one from before the tags existed.
  return value;
}

/**
 * Replace the query string in place.
 *
 * `replaceState`, never `pushState`: these values change on every keystroke in
 * the policy editor, and a back button with four hundred entries in it is a
 * broken back button.
 */
export function writeQuery(params) {
  const query = params.toString();
  const next = query ? `${location.pathname}?${query}` : location.pathname;
  if (next !== location.pathname + location.search) history.replaceState(null, '', next);
}

export function debounce(fn, ms) {
  let timer = 0;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
