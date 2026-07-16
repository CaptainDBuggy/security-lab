FROM python:3.12-slim

# `zip` is needed at build time to produce a legacy ZipCrypto-encrypted bundle.
RUN apt-get update && apt-get install -y --no-install-recommends zip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static/ /app/static/

# ---------------------------------------------------------------------------
# Build the encrypted artifact store.
#   - banner.png is the SAME file served publicly at /static/banner.png, so the
#     learner has its plaintext -> known-plaintext attack against ZipCrypto.
#   - flag3.txt and vault_hashes.txt are the payoff, only readable after bkcrack.
#   - stored with -0 (no compression) so the archived bytes equal the raw file,
#     which keeps the known-plaintext attack clean.
#   - the archive password is random and never disclosed anywhere; recovering it
#     is NOT the intended path (the keystream is, via known plaintext).
# ---------------------------------------------------------------------------
RUN mkdir -p /app/artifacts /tmp/bundle \
 && cp /app/static/banner.png /tmp/bundle/banner.png \
 && printf 'FLAG{z1pcrypt0_kn0wn_pl41nt3xt_bkcr4ck}\n' > /tmp/bundle/flag3.txt \
 && printf '# Cogwheel CI - deploy service credential store (sha512crypt)\n# rotate quarterly; do NOT ship in build artifacts\nsvc_deploy:$6$lcr81F0J9j6GF7St$yn81fz57ZScNYp1a0RijnKG4Zoy.D31yNBGJoyDsNLR7KPQdD7Ykhg4I3zTpkoKOyJVHnQ4T4b0JfkoJOCPoH1\n' > /tmp/bundle/vault_hashes.txt \
 && cd /tmp/bundle \
 && zip -0 -P d8f4b1a6c93e47f2ae10c5b7d92f6a3e /app/artifacts/ci-artifacts-8f2a91.zip \
        banner.png flag3.txt vault_hashes.txt \
 && printf '[build#42] pipeline green\n[build#42] artifacts bundled -> ci-artifacts (encrypted)\n[build#42] deploy vault sealed\n' > /app/artifacts/build.log \
 && rm -rf /tmp/bundle

ENV ARTIFACT_BUNDLE=ci-artifacts-8f2a91.zip

EXPOSE 5000
CMD ["python", "app.py"]
