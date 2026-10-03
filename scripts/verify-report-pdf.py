"""Development-only PDF QA. Requires PyMuPDF; never shipped in the app.

Run node scripts/report-qa.mjs first. Rendered PNGs still require visual review.
"""
import json
import re
from pathlib import Path
import pymupdf


def compact(text):
    return re.sub(r"\s+", "", text)


bundle = json.loads(Path('tmp/pdfs/example-report.json').read_text())
for name, path in [('sample', 'output/pdf/stride-example-report.pdf'), ('long-notes', 'tmp/pdfs/long-notes.pdf')]:
    doc = pymupdf.open(path)
    pages = [page.get_text() for page in doc]
    full = compact('\n'.join(pages))
    assert '\x00' not in full, f'{name}: missing glyph'
    for threat in bundle['model']['threats'].values():
        assert f"Threat{threat['id']}:" in full, f"{name}: lost threat {threat['id']}"
    headings = 0
    for index, page in enumerate(doc):
        extracted = compact(pages[index])
        assert f'Page{index + 1}of{len(doc)}' in extracted, f'{name}: footer {index + 1}'
        assert len(extracted) > 100, f'{name}: empty page {index + 1}'
        for x0, y0, x1, y1, *_ in page.get_text('blocks'):
            assert x0 >= 38 and x1 <= page.rect.width - 38, (name, index + 1, 'horizontal clipping')
            assert y0 >= 20 and y1 <= page.rect.height - 20, (name, index + 1, 'vertical clipping')
        # Threat headers may repeat on continuation pages. An interaction
        # heading must have a threat header after it on the same page.
        for match in re.finditer(r'Interaction ID:', pages[index]):
            headings += 1
            assert re.search(r'Threat \d+:', pages[index][match.end():]), (name, index + 1, 'stranded interaction heading')
    expected = sum(len(c['interactions']) for c in bundle['report']['categories'])
    assert headings == expected, (name, 'lost interaction headings', headings, expected)
    if name == 'long-notes':
        for number in range(1, 451):
            assert full.count(f'Evidence-{number:04}:') == 1, f'lost/duplicated evidence paragraph {number}'
        assert 'END-OF-LONG-NOTES' in full, 'lost final note marker'
        assert full.count('traceablereference.') == 450, 'lost note text'
        end_page = next(i for i, value in enumerate(pages) if 'END-OF-LONG-NOTES' in compact(value))
        doc[end_page].get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5)).save('tmp/pdfs/long-notes-end.png')
    else:
        for i in [0, 1, 4, 5, len(doc) - 1]:
            doc[i].get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5)).save(f'tmp/pdfs/final-page-{i + 1}.png')
    # Contact sheet of every page, followed by detailed visual inspection.
    sheet = pymupdf.open()
    target = sheet.new_page(width=4 * 220, height=((len(doc) + 3) // 4) * 320)
    for i, page in enumerate(doc):
        x, y = (i % 4) * 220, (i // 4) * 320
        target.show_pdf_page(pymupdf.Rect(x, y, x + 220, y + 310), doc, i)
    target.get_pixmap().save(f'tmp/pdfs/{name}-contact.png')
    print(f'{name}: {len(doc)} pages, all threats and {headings} interaction headings retained; bounds, footers and note content passed')
