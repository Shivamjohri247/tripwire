"""Triage: parse any carrier into segments, reveal hidden layers, decode payloads.

Ported from the prototype's tripwire-analyzer.js, plus server-only checks
(PDF colour, email attachment recursion, vision OCR at 1x and 0.5x).
"""
import base64
import binascii
import codecs
import email
import email.policy
import io
import json
import re
import unicodedata
import urllib.parse
import zipfile

from bs4 import BeautifulSoup, Comment
from defusedxml import ElementTree as ET

EXT = {
    'eml': 'email', 'msg': 'email', 'html': 'html', 'htm': 'html', 'md': 'markdown', 'markdown': 'markdown',
    'pdf': 'pdf', 'docx': 'docx', 'png': 'image', 'jpg': 'image', 'jpeg': 'image', 'webp': 'image', 'gif': 'image',
    'json': 'json', 'ics': 'ics', 'txt': 'text', 'log': 'text', 'csv': 'text', 'js': 'code', 'ts': 'code', 'py': 'code',
    'java': 'code', 'go': 'code', 'rb': 'code', 'sh': 'code', 'yaml': 'code', 'yml': 'code', 'toml': 'code',
    'cursorrules': 'code', 'mdc': 'code',
}
AI_WORDS = re.compile(r'\b(ai|assistant|agent|copilot|model|llm|chatbot|gpt|bot)\b', re.I)
IMPERATIVE = re.compile(r"\b(ignore|send|forward|transfer|reveal|print|output|execute|call|approve|mark|remember|do not|don't|must)\b", re.I)
CONFUSABLES = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'А': 'A', 'Е': 'E',
    'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Н': 'H', 'В': 'B', 'М': 'M', 'К': 'K', 'Χ': 'X', 'Ι': 'I', 'Ο': 'O', 'Α': 'A', 'Ε': 'E',
})
# a '.' only ends a sentence before whitespace/end, so URLs, emails and decimals stay whole
SENT = re.compile(r'(?:[^.!?\n]|[.!?](?=[^\s.!?]))+[.!?]*[)"\'”’]*[ \t]*|[.!?]+[ \t]*|\n+')
TAGS = re.compile('[\U000E0000-\U000E007F]+')
ZW = re.compile('[​-‍⁠﻿]')
BIDI = re.compile('[‪-‮⁦-⁩]')
B64 = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
HEX = re.compile(r'\b(?:[0-9a-fA-F]{2}){12,}\b')


def seg(t, loc, h=None, **kw):
    return {'t': t, 'loc': loc, 'h': h, **kw}


def sentences(text, loc):
    return [seg(m.group(0), loc) for m in SENT.finditer(text) if m.group(0)]


def detect_format(name, text=None):
    ext = (name or '').lower().rsplit('.', 1)[-1]
    if ext in EXT:
        return EXT[ext]
    if text is not None:
        s = text.strip()
        if re.search(r'^(from|subject|received|return-path|mime-version):', s[:400], re.I | re.M) and re.search(r'\n\s*\n', s):
            return 'email'
        if re.match(r'BEGIN:VCALENDAR', s, re.I):
            return 'ics'
        if s[:1] in '[{':
            try:
                json.loads(s)
                return 'json'
            except ValueError:
                pass
        if re.search(r'<(html|body|div|p|span|!--)[\s>]', s, re.I):
            return 'html'
        if re.search(r'^#{1,6}\s|\]\(https?:', s, re.M):
            return 'markdown'
    return 'text'


def printable(s):
    return sum(1 for c in s if c.isprintable() or c in '\n\r\t') / len(s) if s else 0


# ---------- parsers ----------
INLINE = {'a', 'span', 'b', 'i', 'em', 'strong', 'u', 'small', 'font', 'sub', 'sup', 'code', 'mark', 'label', 'abbr'}
HIDDEN_CLASS = re.compile(r'\.([\w-]+)\s*\{[^}]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?![.\d]*[1-9]))[^}]*\}', re.I)


def _hidden_of(el, hidden_classes):
    while el is not None and getattr(el, 'name', None) and el.name != '[document]':
        tag = el.name
        if tag in ('script', 'style', 'template', 'title'):
            return 'skip'
        if tag == 'noscript':
            return 'noscript'
        if el.has_attr('hidden'):
            return 'hidden_attr'
        if any(c in hidden_classes for c in el.get('class', [])):
            return 'css_class'
        st = re.sub(r'\s+', '', (el.get('style') or '').lower())
        if st:
            if 'display:none' in st:
                return 'display_none'
            if 'visibility:hidden' in st:
                return 'visibility_hidden'
            if re.search(r'(^|;)opacity:0(\.0+)?(;|$)', st):
                return 'opacity_0'
            fs = re.search(r'font-size:([\d.]+)(px|pt|em|rem|%)?', st)
            if fs:
                v, u = float(fs.group(1)), fs.group(2) or 'px'
                if (v < 2 if u in ('px', 'pt') else v < 15 if u == '%' else v < 0.15):
                    return 'tiny_font'
            if re.search(r'(^|;)color:(#fff(fff)?|white|rgb\(255,255,255\)|#fefefe|#fdfdfd)(;|$|!)', st):
                return 'white_text'
            if re.search(r'(left|top|text-indent|margin-left):-\d{3,}', st):
                return 'offscreen'
            if re.search(r'(^|;)(max-)?height:0', st) and 'overflow:hidden' in st:
                return 'zero_height'
        el = el.parent
    return None


def _block_of(el):
    while el is not None and el.name in INLINE:
        el = el.parent
    return el


def html_segs(html):
    soup = BeautifulSoup(html, 'html.parser')
    hidden_classes = {m.group(1) for s in soup.find_all('style') for m in HIDDEN_CLASS.finditer(s.get_text())}
    segs, buf, last_block, last_hidden = [], '', None, None

    def flush():
        nonlocal buf
        if buf.strip():
            segs.extend(sentences(re.sub(r'[ \t]+', ' ', buf), 'body'))
        buf = ''

    root = soup.body or soup
    for node in root.descendants:
        if isinstance(node, Comment):
            c = node.strip()
            if c:
                flush()
                segs.append(seg(c, '<!-- comment -->', 'html_comment'))
            continue
        if getattr(node, 'name', None) == 'br':
            buf += '\n'
            continue
        if not isinstance(node, str) or node.__class__.__name__ not in ('NavigableString',):
            continue
        txt = str(node)
        if not txt.strip():
            if '\n' in txt:
                buf += ' '
            continue
        h = _hidden_of(node.parent, hidden_classes)
        if h == 'skip':
            continue
        b = _block_of(node.parent)
        if h:
            flush()
            if last_hidden and last_hidden['h'] == h and last_hidden['_el'] is b:
                last_hidden['t'] += ' ' + txt.strip()
            else:
                last_hidden = seg(txt.strip(), f'<{node.parent.name}> {h}', h, _el=b)
                segs.append(last_hidden)
            continue
        last_hidden = None
        if last_block is not None and b is not last_block:
            buf += '\n'
        last_block = b
        buf += txt
    flush()
    for e in soup.find_all(attrs={'alt': True}) + soup.find_all(attrs={'title': True}) + soup.find_all(attrs={'aria-label': True}):
        for a in ('alt', 'title', 'aria-label'):
            v = e.get(a)
            if v and len(v.strip()) > 12:
                segs.append(seg(v.strip(), f'@{a}', 'attribute'))
    for m in soup.find_all('meta', content=True):
        v = m['content']
        if len(v) > 24 and re.search(r'\s', v):
            segs.append(seg(v, f"<meta {m.get('name') or m.get('property') or ''}>", 'meta'))
    for s in segs:
        s.pop('_el', None)
    return {'segs': segs, 'title': soup.title.string.strip() if soup.title and soup.title.string else None}


def md_segs(text):
    segs, last = [], 0
    for m in re.finditer(r'<!--([\s\S]*?)-->|\[[^\]]*\]:\s*\S+\s+"([^"]+)"', text):
        if m.start() > last:
            segs.extend(sentences(text[last:m.start()], 'markdown'))
        is_comment = m.group(1) is not None
        segs.append(seg((m.group(1) if is_comment else m.group(2)).strip(), '<!-- -->' if is_comment else 'reference link title',
                        'md_comment' if is_comment else 'link_title'))
        last = m.end()
    segs.extend(sentences(text[last:], 'markdown'))
    for m in re.finditer(r'<[a-z][^>]*style=["\'][^"\']*(display\s*:\s*none|font-size\s*:\s*0)[^"\']*["\'][^>]*>([\s\S]*?)</[a-z]+>', text, re.I):
        segs.append(seg(m.group(2).strip(), 'inline html', 'inline_html_hidden'))
    return {'segs': segs}


def json_segs(text):
    try:
        o = json.loads(text)
    except ValueError:
        return {'segs': sentences(text, 'text'), 'note': 'JSON parse failed; scanned as text'}
    segs = []

    def walk(v, p):
        if isinstance(v, str):
            if v.strip():
                segs.append(seg(f'{p}: {v}\n', p))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f'{p}[{i}]')
        elif isinstance(v, dict):
            for k, x in v.items():
                if len(k) > 30 or re.search(r'\s', k):
                    segs.append(seg(f'key: {k}\n', f'{p} (key)'))
                walk(x, f'{p}.{k}')
    walk(o, '$')
    return {'segs': segs}


def code_segs(text):
    return {'segs': [seg(line + '\n', f'line {i + 1}') for i, line in enumerate(text.split('\n'))]}


def ics_segs(text):
    unf = re.sub(r'\r?\n[ \t]', '', text)
    segs = []
    for line in re.split(r'\r?\n', unf):
        m = re.match(r'^(SUMMARY|DESCRIPTION|LOCATION|COMMENT|X-[\w-]+|ATTENDEE[^:]*|ORGANIZER[^:]*)[;:](.*)$', line, re.I)
        if m:
            k = m.group(1).split(';')[0]
            segs.append(seg(f"{k}: {m.group(2).replace(chr(92) + 'n', chr(10)).replace(chr(92) + ',', ',')}\n", k))
    return {'segs': segs or sentences(text, 'ics')}


def _near_white(c):
    return all(((c >> s) & 255) >= 240 for s in (16, 8, 0))


def pdf_segs(data):
    import pymupdf
    doc = pymupdf.open(stream=data, filetype='pdf')
    segs = []
    for k in ('subject', 'keywords', 'title', 'author'):
        v = (doc.metadata or {}).get(k) or ''
        if len(v) > 20:
            segs.append(seg(v, f'metadata /{k.title()}', 'metadata'))
    for pno, page in enumerate(doc, 1):
        if pno > 40:
            break
        rect, vis, loc = page.rect, '', f'page {pno}'
        for block in page.get_text('dict')['blocks']:
            for line in block.get('lines', []):
                for sp in line['spans']:
                    txt = sp['text']
                    if not txt.strip():
                        continue
                    x0, y0, x1, y1 = sp['bbox']
                    h = ('tiny_font' if sp['size'] < 2 else 'white_text' if _near_white(sp['color'])
                         else 'off_page' if x1 < rect.x0 or y1 < rect.y0 or x0 > rect.x1 or y0 > rect.y1 else None)
                    if h:
                        if vis.strip():
                            segs.extend(sentences(vis, loc))
                        vis = ''
                        if segs and segs[-1]['h'] == h and segs[-1]['loc'] == loc:
                            segs[-1]['t'] += txt
                        else:
                            segs.append(seg(txt, loc, h))
                    else:
                        vis += txt
                vis += '\n'
        if vis.strip():
            segs.extend(sentences(vis, loc))
        for a in page.annots() or []:
            c = (a.info or {}).get('content') or ''
            if len(c) > 8:
                segs.append(seg(c, f'page {pno} annotation', 'annotation'))
    return {'segs': segs, 'pages': doc.page_count}


W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


class LimitExceeded(ValueError):
    """Content that trips a resource limit. Always QUARANTINE: never treated as merely unparsed (which can fail open)."""


MAX_UNZIPPED = 50 * 1048576  # a DOCX may not expand past 50 MB in total (zip-bomb guard)
MAX_DECODES = 50  # base64/hex decodes per segment


def docx_segs(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
        raise LimitExceeded('Word archive expands past the 50 MB limit')
    raw = []

    def parse(path, loc):
        if path not in z.namelist():
            return
        root = ET.fromstring(z.read(path))
        for p in root.iter(W + 'p'):
            cur = None
            for r in p.iter(W + 'r'):
                txt = ''.join(t.text or '' for t in r.iter(W + 't'))
                if not txt:
                    continue
                h, rpr = None, r.find(W + 'rPr')
                if rpr is not None:
                    v = rpr.find(W + 'vanish')
                    if v is not None and v.get(W + 'val') not in ('0', 'false'):
                        h = 'w_vanish'
                    c = rpr.find(W + 'color')
                    if not h and c is not None and (c.get(W + 'val') or '').upper() in ('FFFFFF', 'FEFEFE', 'FDFDFD'):
                        h = 'white_text'
                    sz = rpr.find(W + 'sz')
                    if not h and sz is not None and (sz.get(W + 'val') or '').isdigit() and int(sz.get(W + 'val')) < 4:
                        h = 'tiny_font'
                if cur and cur['h'] == h:
                    cur['t'] += txt
                else:
                    cur = seg(txt, loc, h)
                    raw.append(cur)
            if cur:
                cur['t'] += '\n'

    parse('word/document.xml', 'body')
    for n in z.namelist():
        if re.match(r'^word/(header|footer)\d*\.xml$', n):
            parse(n, n[5:-4])
    if 'word/comments.xml' in z.namelist():
        for c in ET.fromstring(z.read('word/comments.xml')).iter(W + 'comment'):
            t = ''.join(x.text or '' for x in c.iter(W + 't'))
            if t.strip():
                raw.append(seg(t, 'comment', 'docx_comment'))
    out = []
    for s in raw:
        out.extend([s] if s['h'] else sentences(s['t'], s['loc']))
    return {'segs': out}


def eml_segs(raw_bytes):
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    if not any(msg.get(k) for k in ('From', 'Subject', 'To', 'Date', 'Content-Type')):
        return {'segs': sentences(raw_bytes.decode('utf-8', 'replace'), 'body')}
    segs, html, plain, atts = [], None, None, []
    if msg['Subject']:
        segs.append(seg(f"Subject: {msg['Subject']}\n", 'Subject'))
    for part in msg.walk():
        if part.is_multipart():
            continue
        name, ct = part.get_filename(), part.get_content_type()
        if name:
            atts.append((name, part.get_payload(decode=True) or b''))
        elif ct == 'text/html' and html is None:
            html = part.get_content()
        elif ct == 'text/plain' and plain is None:
            plain = part.get_content()
    if html:
        segs.extend(html_segs(html)['segs'])
    elif plain:
        segs.extend(sentences(plain, 'text/plain'))
    if html and plain:
        html_text = re.sub(r'\s+', ' ', ' '.join(s['t'] for s in segs))
        for s in sentences(plain, 'text/plain'):
            k = re.sub(r'\s+', ' ', s['t'].strip())
            if len(k) > 20 and k not in html_text:
                segs.append(seg(s['t'], 'text/plain (not in html)', 'plain_only_part'))
    return {'segs': segs, 'title': msg['Subject'], 'from': msg['From'], 'attachments': atts}


# ---------- reveal / decode ----------
def rot13(s):
    return codecs.encode(s, 'rot13')


def reveal(segs, notes, looks_malicious, depth_max=3):
    out = []
    for s in segs:
        pieces = [s]
        if TAGS.search(s['t']):
            pieces, last = [], 0
            for m in TAGS.finditer(s['t']):
                if m.start() > last:
                    pieces.append({**s, 't': s['t'][last:m.start()]})
                dec = re.sub(r'[\x00-\x1f]', '', ''.join(chr(ord(c) - 0xE0000) for c in m.group(0)))
                pieces.append(seg(dec, s['loc'], 'unicode_tags', enc=True, encodings=['unicode_tags']))
                notes.append(f'Decoded {len(m.group(0))} Unicode-tag chars → ASCII')
                last = m.end()
            if last < len(s['t']):
                pieces.append({**s, 't': s['t'][last:]})
        for p in pieces:
            for rx, name, label in ((ZW, 'zero_width', 'zero-width chars'), (BIDI, 'bidi', 'bidi overrides')):
                n = len(rx.findall(p['t']))
                if n:
                    p['t'] = rx.sub('', p['t'])
                    p['encodings'] = [*p.get('encodings', []), name]
                    p['enc'] = True
                    notes.append(f'Stripped {n} {label}')
            norm = unicodedata.normalize('NFKC', p['t'])
            mapped = norm.translate(CONFUSABLES)
            homo = sum(1 for a, b in zip(norm, mapped) if a != b)
            if homo and re.search(r'[a-z]', p['t'], re.I):
                p['dec'] = mapped
                p['encodings'] = [*p.get('encodings', []), 'homoglyph']
                p['enc'] = True
                notes.append(f'Mapped {homo} homoglyphs to Latin')
            out.extend(decode_inline(p, notes, looks_malicious, 0, depth_max))
    return [s for s in out if s['t'] != '']


def decode_inline(p, notes, looks_malicious, depth, depth_max, budget=None):
    budget = budget if budget is not None else [MAX_DECODES]  # shared across the recursion for one segment
    if depth >= depth_max:
        return [p]
    if budget[0] <= 0 and B64.search(p.get('dec') or p['t']):  # undecoded payloads left: refuse rather than pass them unread
        raise LimitExceeded(f'more than {MAX_DECODES} encoded payloads in one segment')
    src = p.get('dec') or p['t']
    for m in B64.finditer(src):
        try:
            d = base64.b64decode(m.group(0), validate=True).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if printable(d) >= 0.9 and re.search(r'[a-z]{3,}\s+[a-z]{2,}', d, re.I):
            budget[0] -= 1
            notes.append(f'Decoded base64 ({len(m.group(0))} chars)')
            before, after = src[:m.start()], src[m.end():]
            mid = seg(m.group(0), p['loc'], 'encoded:base64', dec=d, vis=True, enc=True, encodings=[*p.get('encodings', []), 'base64'])
            base = {k: v for k, v in p.items() if k != 'dec'}
            return ([{**base, 't': before}] if before else []) + decode_inline(mid, notes, looks_malicious, depth + 1, depth_max, budget) + \
                (decode_inline({**base, 't': after}, notes, looks_malicious, depth, depth_max, budget) if after else [])
    hm = HEX.search(src)
    if hm:
        try:
            d = bytes.fromhex(hm.group(0)).decode('utf-8')
            if printable(d) > 0.95 and re.search(r'[a-z]{3,}\s', d, re.I):
                notes.append('Decoded hex payload')
                return [{**p, 'dec': src.replace(hm.group(0), d), 'encodings': [*p.get('encodings', []), 'hex'], 'enc': True,
                         'h': p['h'] or 'encoded:hex', 'vis': not p['h']}]
        except (ValueError, UnicodeDecodeError):
            pass
    if len(re.findall(r'%[0-9a-f]{2}', src, re.I)) >= 6:
        d = urllib.parse.unquote(src)
        if d != src:
            notes.append('Decoded URL-encoding')
            return [{**p, 'dec': d, 'encodings': [*p.get('encodings', []), 'url'], 'enc': True}]
    if re.search(r'rot13', src, re.I) or re.search(r'\b(vtaber|cerivbhf|vafgehpgvbaf|flfgrz)\b', src, re.I):
        r = rot13(src)
        if looks_malicious(r):
            notes.append('Decoded ROT13')
            return [{**p, 'dec': r, 'encodings': [*p.get('encodings', []), 'rot13'], 'enc': True, 'h': p['h'] or 'encoded:rot13', 'vis': not p['h']}]
    return [p]


def is_hidden(s):
    return bool(s.get('h')) and not s.get('vis')


def text_of(s):
    return s.get('dec') or s['t']


def parse(data, fmt):
    """Parse bytes of a non-image carrier → {'segs', 'title'?, 'note'?, 'pages'?, 'attachments'?}. Images are OCR'd by the pipeline."""
    text = None if fmt in ('pdf', 'docx', 'image') else data.decode('utf-8', 'replace')
    if fmt == 'pdf':
        return pdf_segs(data)
    if fmt == 'docx':
        return docx_segs(data)
    if fmt == 'email':
        return eml_segs(data)
    if fmt == 'html':
        return html_segs(text)
    if fmt == 'markdown':
        return md_segs(text)
    if fmt == 'json':
        return json_segs(text)
    if fmt == 'ics':
        return ics_segs(text)
    if fmt == 'code':
        return code_segs(text)
    return {'segs': sentences(text, 'text')}
