Bundled PDF assets
==================

The PDF renderer and fonts are distributed inside the app, including its standalone HTML build. No
runtime installation, CDN, URL font loading, or external image loading is used. The application supplies
only its own report definition, embedded font data and locally rendered SVG. pdfmake's URL access policy
is set to reject every URL; the application's CSP independently blocks network connections.

- **pdfmake 0.3.11**, MIT: https://github.com/bpampuch/pdfmake
  - Source: `https://registry.npmjs.org/pdfmake/-/pdfmake-0.3.11.tgz`
  - Registry integrity: `sha512-Uc49J9hUMyuqJk+U+PxlpBpPr96A4HOOfesGx609EPr2ue82+5/Smq/KTAkEqh0/jUGSi1fumvqZ5yAWijJTJg==`
  - `build/pdfmake.min.js` is wrapped in a local CommonJS scope and exported as an ES module in
    `js/vendor/pdfmake.js`. The unused source-map reference is removed. Rendering code is unchanged.
  - License: `js/vendor/PDFMAKE-LICENSE.txt`.
- **Roboto**, Apache 2.0: https://github.com/googlefonts/roboto-2
  - Font bytes come from the same pinned pdfmake distribution's `build/vfs_fonts.js`.
  - `js/vendor/fonts.js` exports the VFS dictionary without global registration.
  - License: `js/vendor/ROBOTO-LICENSE.txt`.
  - `js/vendor/font-coverage.js` records the Regular font's Unicode coverage for missing-glyph checks.

The local asset SHA-256 hashes are recorded in `js/vendor/manifest.json` and checked by `npm test`.
Updating the library requires regenerating those hashes and rerunning PDF rendering, offline-network,
pagination and model round-trip checks.
