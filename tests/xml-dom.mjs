import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

class Element {
  constructor(data) { Object.assign(this, data); this.children = data.children.map((child) => new Element(child)); }
  getAttributeNS(namespace, name) { return this.attributes[`{${namespace}}${name}`] ?? null; }
}

export class TestDOMParser {
  parseFromString(xml) {
    const parsed = spawnSync('python3', [fileURLToPath(new URL('./xml-dom.py', import.meta.url))], { input: xml, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    if (parsed.status !== 0) throw new Error(`Test XML parser failed: ${parsed.stderr}`);
    const documentElement = new Element(JSON.parse(parsed.stdout));
    const all = (el) => [el, ...el.children.flatMap(all)];
    return { documentElement, getElementsByTagNameNS: (namespace, name) => all(documentElement).filter((el) =>
      (namespace === '*' || namespace === el.namespaceURI) && (name === '*' || name === el.localName)) };
  }
}
