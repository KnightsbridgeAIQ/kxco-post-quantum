# Third-implementation interop peer: liboqs (Open Quantum Safe).
#
# liboqs is C and needs a toolchain this repo does not assume any contributor
# has, so the peer runs in a container instead. The image pins liboqs by tag and
# liboqs-python by tag and commit; the tags are recorded in peers-lock.json.
#
# libssl-dev is not optional: liboqs 0.16.0 configures against OpenSSL for its
# symmetric primitives and cmake fails at find_package(OpenSSL) without it.
#
# Built and driven by ../run-interop.mjs. Speaks the same one-JSON-object-per-line
# protocol on stdin/stdout as the other peers.

# Pinned by digest, not just by tag. This image builds the liboqs peer whose
# output appears in the published interop matrix, and a floating tag means a
# rebuild months from now compares against a different peer than the one the
# evidence describes. A conformance harness that cannot be rebuilt to the same
# bytes is not reproducible, whatever the README says.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG LIBOQS_TAG=0.16.0
ARG LIBOQS_PYTHON_TAG=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${LIBOQS_TAG} \
      https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && ldconfig \
 && rm -rf /tmp/liboqs

# liboqs-python is pinned three ways, so no step fetches anything unpinned: the
# tag must resolve to this commit, the build tools (hatchling and its
# dependencies) install by sha256 from liboqs-build-requirements.txt, and the
# wheel is built with --no-build-isolation so pip uses those rather than
# downloading hatchling itself. Bump the commit together with LIBOQS_PYTHON_TAG.
ARG LIBOQS_PYTHON_COMMIT=c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061
COPY liboqs-build-requirements.txt /tmp/liboqs-build-requirements.txt

RUN git clone --depth 1 --branch ${LIBOQS_PYTHON_TAG} \
      https://github.com/open-quantum-safe/liboqs-python /tmp/liboqs-python \
 && test "$(git -C /tmp/liboqs-python rev-parse HEAD)" = "${LIBOQS_PYTHON_COMMIT}" \
 && pip install --no-cache-dir --require-hashes -r /tmp/liboqs-build-requirements.txt \
 && pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /tmp/wheels /tmp/liboqs-python \
 && pip install --no-cache-dir --no-deps /tmp/wheels/*.whl \
 && rm -rf /tmp/liboqs-python /tmp/wheels /tmp/liboqs-build-requirements.txt

COPY liboqs-peer.py /peer/liboqs-peer.py
ENTRYPOINT ["python", "-u", "/peer/liboqs-peer.py"]
