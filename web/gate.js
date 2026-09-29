// Page side of the gate: register the worker, configure a view, get a URL.
//
// Everything a reader needs is a URL. That is the whole interface, and it is
// why a reader added later -- hyparquet, duckdb-wasm, geotiff.js, anything --
// needs no cooperation from this file: it fetches, and the worker answers.

const SCOPE = new URL('./', location.href);

let registration = null;
let nextId = 0;

/** Is a service worker even possible here? */
export const supported = () => 'serviceWorker' in navigator;

/**
 * Register the worker and wait until it controls this page.
 *
 * The wait matters. A worker that is installed but not yet *controlling*
 * does not see this page's requests, so a reader started too early fetches
 * straight past the gate and reads the unfiltered object -- which would look
 * like the policy silently failing.
 */
export async function start() {
  if (!supported()) {
    throw new Error(
      'This browser has no service worker, so there is nowhere to put the gate. '
      + 'The page needs one to answer a reader\'s requests with filtered bytes.',
    );
  }
  if (registration) return registration;
  registration = await navigator.serviceWorker.register(
    new URL('./sw.js', import.meta.url),
    { type: 'module', scope: SCOPE.pathname },
  );
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    // First load after a hard refresh: the worker is active but took control
    // only for the *next* navigation. Claiming is asynchronous, so wait for it
    // rather than reloading the page under the user.
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true });
      setTimeout(resolve, 2000);
    });
  }
  return registration;
}

/** One request/response exchange with the worker, matched on `id`. */
function ask(message) {
  return new Promise((resolve, reject) => {
    const onMessage = (event) => {
      if (event.data?.id !== message.id) return;
      navigator.serviceWorker.removeEventListener('message', onMessage);
      clearTimeout(timer);
      if (event.data.type === 'failed') reject(new Error(event.data.message));
      else resolve(event.data);
    };
    const timer = setTimeout(() => {
      navigator.serviceWorker.removeEventListener('message', onMessage);
      reject(new Error('the gate did not answer within 30 seconds'));
    }, 30000);
    navigator.serviceWorker.addEventListener('message', onMessage);
    navigator.serviceWorker.controller?.postMessage(message);
  });
}

/**
 * Put a file behind a policy and return a URL that serves it.
 *
 * `mode` is `'refuse'` -- deny any range covering withheld bytes, with a real
 * 403 -- or `'filter'`, which serves a rewritten view and never refuses.
 *
 * The returned `url` is same-origin and ordinary. Point anything at it.
 */
export async function open({ url, format, policy, user, mode }) {
  await start();
  const id = `g${(nextId += 1)}-${Date.now().toString(36)}`;
  const info = await ask({ type: 'configure', id, url, format, policy, user, mode });
  return {
    id,
    // A name with the right extension: duckdb-wasm and GDAL both sniff format
    // from the path before they read a byte.
    url: new URL(`./gate/${id}/object.${format === 'parquet' ? 'parquet' : 'tif'}`, SCOPE).href,
    size: info.size,
    virtualSize: info.virtualSize,
    window: info.window,
    regionCount: info.regionCount,
    regions: JSON.parse(info.regions),
    withheld: info.withheld ? JSON.parse(info.withheld) : null,
    scrub: info.scrub,
    etag: info.etag,
    planError: info.planError,
    /** What is in `[start, end)`? The resolver alone — no fetch, no bytes. */
    resolve: (start, end) => ask({ type: 'resolve', id, start, end }),
    release: () => navigator.serviceWorker.controller?.postMessage({ type: 'release', id }),
  };
}
