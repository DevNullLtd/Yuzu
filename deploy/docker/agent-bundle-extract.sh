#!/bin/sh
# Entrypoint for the Yuzu agent-bundle delivery image (busybox sh).
#   docker run --rm -v "$PWD:/out" <img>   -> copies the tree to ./yuzu-agents/
#   docker run --rm <img> list             -> recursive listing
#   docker run --rm <img> sh               -> a busybox shell
#   docker run --rm <img>                  -> prints the bundle README
set -e
SRC=/opt/yuzu-agents
case "${1:-}" in
  sh|/bin/sh) exec /bin/sh ;;
  list|ls)    exec ls -R "$SRC" ;;
esac
if [ -d /out ]; then
  echo "Yuzu agent bundle $(cat "$SRC/VERSION") -> /out/yuzu-agents"
  cp -a "$SRC" /out/
  echo "done. cd /out/yuzu-agents && sha256sum -c SHA256SUMS only shows the tree is intact;"
  echo "what shows it is genuine is the image signature: cosign verify <image> (see README.txt, Integrity)."
else
  cat "$SRC/README.txt"
  echo
  echo '(mount a dir at /out to self-extract: docker run --rm -v "$PWD:/out" <img>)'
fi
