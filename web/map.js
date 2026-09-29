// A pannable, zoomable view of a COG, read tile by tile through the gate.
//
// This is the demonstration that needs no explaining: pan over Paris, zoom in,
// and the Eiffel Tower is a black square. Change the policy and it is back.
//
// Every tile the map draws is a separate range request to the gate, so the
// policy is applied per tile at whatever zoom is on screen -- exactly as a
// gateway would, and exactly where a naive implementation would leak: the
// overviews are their own tiles and they need their own rule.
//
// Coordinates are the full-resolution image's own pixels, with the origin at
// the top left. Using an orthographic view rather than a map projection keeps
// the file's CRS out of the rendering entirely: whatever a COG is georeferenced
// to, its pixel grid is a rectangle, and that is all this needs.

let deckPromise = null;
let geotiffPromise = null;

const DECK = 'https://cdn.jsdelivr.net/npm/deck.gl@9.0.35/dist.min.js';

/**
 * deck.gl from its UMD bundle rather than as an ES module.
 *
 * The umbrella package does not survive a CDN's automatic ESM conversion --
 * `deck.gl@9/+esm` loads and then throws reading `prototype` off an undefined
 * base class, because the re-export graph is resolved wrongly. The UMD build
 * is one file and one global, which is exactly what a page loading from a CDN
 * wants anyway.
 */
const deckgl = () => (deckPromise ??= new Promise((resolve, reject) => {
  if (window.deck) { resolve(window.deck); return; }
  const script = document.createElement('script');
  script.src = DECK;
  script.onload = () => (window.deck ? resolve(window.deck) : reject(new Error('deck.gl loaded but exported nothing')));
  script.onerror = () => reject(new Error(`could not load deck.gl from ${DECK}`));
  document.head.append(script);
}));

const geotiff = () => (geotiffPromise ??= import('https://cdn.jsdelivr.net/npm/geotiff@2.1.3/+esm'));

/**
 * Mount a viewer into `container`.
 *
 * Returns a handle with `update(url)` -- which re-reads everything from a new
 * gate, discarding the tile cache so nothing survives a policy change -- and
 * `destroy()`.
 */
export async function mountMap(container, { url, onStatus }) {
  const [{ Deck, OrthographicView, TileLayer, BitmapLayer }, { fromUrl }] =
    await Promise.all([deckgl(), geotiff()]);

  let tiff = null;
  let images = [];
  let width = 0;
  let height = 0;
  let generation = 0;
  /** How many tiles this reader refused to decode, for the status line. */
  let undecodable = 0;

  async function openTiff(nextUrl) {
    onStatus?.('reading the image…');
    undecodable = 0;
    tiff = await fromUrl(nextUrl);
    const count = await tiff.getImageCount();
    images = [];
    for (let i = 0; i < count; i += 1) images.push(await tiff.getImage(i));
    // geotiff.js orders images fine-to-coarse, which is also the COG's order.
    width = images[0].getWidth();
    height = images[0].getHeight();
    onStatus?.(`${width}×${height}, ${count} levels`);
  }

  await openTiff(url);

  /**
   * What a withheld tile looks like.
   *
   * Deliberately not a plain black rectangle. Black is what GDAL produces from
   * these same bytes, and drawing it here would claim this reader had decoded
   * something it could not. The hatch says "nothing was served for this tile",
   * which is the true statement for every reader.
   */
  function withheldTile(w, h) {
    const data = new Uint8ClampedArray(w * h * 4);
    for (let y = 0; y < h; y += 1) {
      for (let x = 0; x < w; x += 1) {
        const p = (y * w + x) * 4;
        const stripe = ((x + y) % 14) < 7;
        const v = stripe ? 26 : 38;
        data[p] = v;
        data[p + 1] = v;
        data[p + 2] = v;
        data[p + 3] = 255;
      }
    }
    return new ImageData(data, w, h);
  }

  /**
   * Read one screen tile.
   *
   * The overview is chosen from how much ground the tile has to cover, not
   * from the deck.gl zoom index -- the two agree, but the bbox is what is
   * actually being asked for, and deriving from it means the layer cannot
   * disagree with the request.
   */
  async function readTile({ bbox, signal }, mine) {
    // A tile at the edge of the image covers less ground than the grid cell
    // asks for. Clamping the READ without also clamping where the result is
    // DRAWN stretches that partial read across a whole cell, which is a
    // horizontal smear down the last column and the last row.
    const left = Math.max(0, Math.floor(bbox.left));
    const top = Math.max(0, Math.floor(bbox.top));
    const right = Math.min(width, Math.ceil(bbox.right));
    const bottom = Math.min(height, Math.ceil(bbox.bottom));
    if (right <= left || bottom <= top) return null;

    // One output pixel per 256 across the full cell; pick the coarsest image
    // that still has that detail, so a zoomed-out view reads small tiles
    // rather than decimating the full-resolution ones.
    const wanted = (bbox.right - bbox.left) / 256;
    let level = 0;
    for (let i = 0; i < images.length; i += 1) {
      const scale = width / images[i].getWidth();
      if (scale <= wanted) level = i;
    }
    const image = images[level];
    const scale = width / image.getWidth();

    const window = [
      Math.floor(left / scale),
      Math.floor(top / scale),
      Math.ceil(right / scale),
      Math.ceil(bottom / scale),
    ];
    if (window[2] <= window[0] || window[3] <= window[1]) return null;

    // Output size in proportion to the ground actually covered, so a partial
    // tile is a smaller picture rather than a stretched one.
    const outW = Math.max(1, Math.round(((right - left) / (bbox.right - bbox.left)) * 256));
    const outH = Math.max(1, Math.round(((bottom - top) / (bbox.bottom - bbox.top)) * 256));

    let rgb;
    try {
      rgb = await image.readRGB({ window, width: outW, height: outH, signal });
    } catch (err) {
      // geotiff.js cannot read a sparse tile. `TileOffsets[i] == 0` means "never
      // written" and GDAL fills it with nodata; geotiff.js dereferences the
      // missing entry and throws `Cannot read properties of undefined (reading
      // 'offset')`. That is this reader's limit, not a property of the file --
      // GDAL reads the identical bytes and decodes the withheld tiles as
      // zeroes -- so the tile is drawn as withheld and the reader's failure is
      // reported, rather than letting the page background show through and
      // reading as though the gate had served a grey square.
      if (mine !== generation) return null;
      if (!/offset|undefined/i.test(String(err?.message || err))) throw err;
      undecodable += 1;
      onStatus?.(
        `${width}×${height}, ${images.length} levels — ${undecodable} tile`
        + `${undecodable === 1 ? '' : 's'} withheld, which this reader cannot decode`,
      );
      return { image: withheldTile(outW, outH), bounds: [left, bottom, right, top] };
    }
    if (mine !== generation) return null;

    // A withheld tile arrives as zeroes, which is black -- the honest
    // rendering, and the one a GDAL-based client would also produce, since a
    // sparse COG tile reads as nodata.
    const data = new Uint8ClampedArray(outW * outH * 4);
    for (let i = 0, p = 0; p < data.length; i += 3, p += 4) {
      data[p] = rgb[i];
      data[p + 1] = rgb[i + 1];
      data[p + 2] = rgb[i + 2];
      data[p + 3] = 255;
    }
    // The bounds travel with the pixels: only this function knows the read was
    // clamped, so only this function can say where the result belongs.
    return { image: new ImageData(data, outW, outH), bounds: [left, bottom, right, top] };
  }

  const makeLayer = () => new TileLayer({
    id: `cog-${generation}`,
    tileSize: 256,
    extent: [0, 0, width, height],
    minZoom: -6,
    maxZoom: 0,
    maxRequests: 8,
    refinementStrategy: 'no-overlap',
    getTileData: (tile) => readTile(tile, generation),
    renderSubLayers: (props) => {
      if (!props.data) return null;
      const { image, bounds } = props.data;
      return new BitmapLayer(props, { data: undefined, image, bounds });
    },
  });

  const fitZoom = () => Math.log2(Math.min(
    (container.clientWidth || 640) / width,
    (container.clientHeight || 520) / height,
  ));

  let viewState = {
    target: [width / 2, height / 2, 0],
    zoom: fitZoom(),
    minZoom: fitZoom() - 1,
    maxZoom: 3,
  };

  const deck = new Deck({
    parent: container,
    views: new OrthographicView({ id: 'ortho', flipY: true }),
    viewState,
    onViewStateChange: ({ viewState: next }) => {
      viewState = next;
      deck.setProps({ viewState });
    },
    controller: { dragRotate: false, doubleClickZoom: true },
    layers: [makeLayer()],
    style: { position: 'relative' },
  });

  return {
    /** Point the map at a different gate, discarding every cached tile. */
    async update(nextUrl) {
      generation += 1;
      await openTiff(nextUrl);
      deck.setProps({ layers: [makeLayer()] });
    },
    /** Centre on a world-pixel point at a given zoom. */
    flyTo(x, y, zoom) {
      viewState = {
        ...viewState,
        target: [x, y, 0],
        zoom: zoom ?? viewState.zoom,
        transitionDuration: 700,
      };
      deck.setProps({ viewState });
    },
    /** Image pixel coordinates for a point in the file's own CRS. */
    project: null,
    destroy() {
      generation += 1;
      deck.finalize();
    },
    /** Frame the whole image again. */
    fit() {
      viewState = { ...viewState, target: [width / 2, height / 2, 0], zoom: fitZoom(), transitionDuration: 700 };
      deck.setProps({ viewState });
    },
    get size() {
      return { width, height };
    },
  };
}
