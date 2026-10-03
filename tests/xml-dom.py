"""Test-only XML bridge using Python's standard library (no installed packages).

Production uses the browser's native DOMParser. This exposes a small XML tree
to Node so the real importer can run against fixtures without a DOM dependency.
"""
import json
import sys
import xml.etree.ElementTree as ET


def convert(element):
    namespace, _, name = element.tag[1:].partition('}') if element.tag.startswith('{') else ('', '', element.tag)
    return {
        'localName': name, 'namespaceURI': namespace, 'attributes': element.attrib,
        'textContent': ''.join(element.itertext()), 'children': [convert(child) for child in element],
    }


try:
    print(json.dumps(convert(ET.fromstring(sys.stdin.read()))))
except ET.ParseError as error:
    print(json.dumps({'localName': 'parsererror', 'namespaceURI': '', 'attributes': {}, 'textContent': str(error), 'children': []}))
