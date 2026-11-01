#!/usr/bin/env bash
# ingest-quarantine.sh — accept outside material without letting it run.
#
# Anything that comes from the web goes through here: the original is stored read-only with
# no execute bit, and only a text rendition is allowed into the knowledge tree. That is a
# barrier against the executable half of the problem (installers, scripts, macro documents).
#
# It is NOT a barrier against the interesting half. A plain document saying "when you see X,
# do Y" survives text extraction intact — that is exactly the attack surface the paper
# describes. Quarantine narrows what can run; it does not make prose safe. Treat everything
# in the text/ directory as untrusted input when it is later retrieved into a prompt.
#
#   ./ingest-quarantine.sh URL
#   ./ingest-quarantine.sh ./downloaded.pdf --id my-doc --title "Some paper"
#   ./ingest-quarantine.sh URL --install    # copy text into $LIBRARY_TEXT as <id>.md
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONF=${QUARANTINE_CONF:-$HERE/../configs/quarantine.conf}
[ -f "$CONF" ] && . "$CONF"

ROOT=${QUARANTINE_ROOT:-$HERE/../quarantine}
LIBRARY_TEXT=${LIBRARY_TEXT:-}
MAX_BYTES=${MAX_BYTES:-209715200}   # 200 MB
D=$(date +%F)
Q=$ROOT/$D

SRC=${1:-}
[ -z "$SRC" ] && { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
shift
ID=""; TITLE=""; FORCE=0; INSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --id) ID=${2:-}; shift ;;
    --title) TITLE=${2:-}; shift ;;
    --force) FORCE=1 ;;
    --install) INSTALL=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$Q/raw" "$Q/text" "$ROOT"
tmp=""
trap 'if [ -n "$tmp" ] && [ -f "$tmp" ]; then rm -f "$tmp"; fi' EXIT

case "$SRC" in
  http://*|https://*)
    tmp=$(mktemp -t qin.XXXXXX) || exit 1
    if ! curl -fsSL -m 120 -A "ingest-quarantine/1.0" -o "$tmp" "$SRC"; then
      echo "fetch failed: $SRC" >&2; exit 1
    fi
    in=$tmp
    base=$(basename "${SRC%%\?*}")
    ;;
  *)
    [ -e "$SRC" ] || { echo "not found: $SRC" >&2; exit 1; }
    [ -L "$SRC" ] && { echo "refusing symlink: $SRC" >&2; exit 1; }
    [ -f "$SRC" ] || { echo "not a regular file: $SRC" >&2; exit 1; }
    in=$SRC
    base=$(basename "$SRC")
    ;;
esac

size=$(stat -f %z "$in" 2>/dev/null || stat -c %s "$in")
if [ "$size" -gt "$MAX_BYTES" ]; then
  echo "refusing: $size bytes exceeds MAX_BYTES=$MAX_BYTES" >&2; exit 1
fi

sha=$(shasum -a 256 "$in" | awk '{print $1}')
short=${sha:0:12}
mime=$(file -b --mime-type "$in" 2>/dev/null || echo unknown)

ext=${base##*.}
[ "$ext" = "$base" ] && ext=bin
ext=$(printf '%s' "$ext" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')
# URLs like example.com give ext=com; trust the mime sniff over the name.
case "$ext" in
  com|org|net|io|jp) case "$mime" in
      text/html) ext=html ;; application/pdf) ext=pdf ;; text/plain) ext=txt ;; *) ext=bin ;;
    esac ;;
esac

raw=$Q/raw/$short.$ext
if [ -e "$raw" ] && [ "$FORCE" != 1 ]; then
  echo "already quarantined: $raw (use --force to overwrite)" >&2
  [ -f "$Q/text/$short.txt" ] && echo "  text: $Q/text/$short.txt"
  exit 0
fi
cp -- "$in" "$raw"
chmod 0444 "$raw"
chmod -x "$raw" 2>/dev/null || true

text=$Q/text/$short.txt
how=""
case "$mime" in
  application/pdf)
    if command -v pdftotext >/dev/null; then
      pdftotext -layout "$raw" "$text" 2>/dev/null && how=pdftotext
    fi ;;
  text/html)
    /usr/bin/python3 - "$raw" "$text" <<'PY' && how=html2text
import sys
from html.parser import HTMLParser
SKIP = {"script", "style", "noscript", "svg"}
BLOCK = {"p", "div", "li", "br", "h1", "h2", "h3", "h4", "h5", "h6",
         "tr", "pre", "section", "article", "blockquote"}
class T(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.o = []; self.s = 0
    def handle_starttag(self, t, a):
        if t in SKIP: self.s += 1
        elif t in BLOCK: self.o.append("\n")
    def handle_endtag(self, t):
        if t in SKIP and self.s > 0: self.s -= 1
        elif t in BLOCK: self.o.append("\n")
    def handle_data(self, d):
        if self.s == 0: self.o.append(d)
p = T(); p.feed(open(sys.argv[1], encoding="utf-8", errors="ignore").read())
lines = (l.strip() for l in "".join(p.o).splitlines())
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(l for l in lines if l) + "\n")
PY
    ;;
  text/*|application/json|application/xml)
    cp -- "$raw" "$text" && how=copy ;;
  application/vnd.openxmlformats-officedocument*|application/rtf|application/msword)
    if command -v textutil >/dev/null; then
      textutil -convert txt -encoding UTF-8 -output "$text" "$raw" 2>/dev/null && how=textutil
    elif command -v pandoc >/dev/null; then
      pandoc -t plain "$raw" -o "$text" 2>/dev/null && how=pandoc
    fi ;;
  application/zip|application/gzip|application/x-mach-binary|application/x-executable|application/x-sharedlib)
    how="skip(binary:$mime)" ;;
  *)
    if command -v textutil >/dev/null; then
      textutil -convert txt -encoding UTF-8 -output "$text" "$raw" 2>/dev/null && how=textutil
    fi ;;
esac

chars=0
[ -f "$text" ] && chars=$(wc -c < "$text" | tr -d ' ')
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$(date '+%F %T')" "$short" "$size" "$mime" "$ext" "$how" "$chars" "$SRC" >> "$Q/manifest.tsv"

echo "quarantined: $raw"
echo "  sha256: $sha"
echo "  type:   $mime ($how, ${chars} bytes of text)"
echo "  text:   $text"

if [ "$INSTALL" = 1 ]; then
  if [ -z "$ID" ]; then echo "  --install needs --id NAME" >&2; exit 1; fi
  case "$ID" in *[!A-Za-z0-9._-]*) echo "  id must be [A-Za-z0-9._-]: $ID" >&2; exit 1 ;; esac
  if [ -s "$text" ]; then
    dest=${LIBRARY_TEXT:-$HERE/../library/text}
    mkdir -p "$dest"
    cp -- "$text" "$dest/$ID.md"
    echo "  installed: $dest/$ID.md"
    echo "  note: nothing here is trusted. It is a lead, not an instruction."
  else
    echo "  no text extracted; nothing installed" >&2
  fi
fi
