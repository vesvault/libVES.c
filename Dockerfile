# Build of libVES.c + the ves(1) CLI with post-quantum (ML-KEM) support.
#
# This used to copy liboqs out of openquantumsafe/python:b0efd3b. That image
# was last pushed in June 2023 and carries liboqs ~0.8, which is too old for
# lib/libVES/KeyAlgo_OQS.c: the "ML-KEM-512/768/1024" identifiers it passes to
# OQS_KEM_new only exist from liboqs 0.10 (0.8 still spells them "Kyber*"),
# and seed-based key import needs OQS_KEM_keypair_derand from 0.13. liboqs is
# not packaged on Debian/Ubuntu, so build it from a pinned release tag --
# bump LIBOQS_VERSION to move it.
ARG LIBOQS_VERSION=0.16.0
ARG DEBIAN_TAG=bookworm-slim

FROM debian:${DEBIAN_TAG} AS liboqs
ARG LIBOQS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates git cmake ninja-build gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Algorithm selection matches the other VES native builds (see
# vesmail-android:build-aux/android/build-deps.sh): KEMs only, since VES vault
# crypto never uses PQ signatures, minus the three KEMs that are unfit for
# wrapping user keys (BIKE's reference impl, and Classic McEliece / FrodoKEM
# key sizes). KeyAlgo_OQS.c enumerates what is compiled in at runtime via
# OQS_KEM_alg_is_enabled(), so this is exactly what the image surfaces.
#
# OQS_DIST_BUILD keeps the result portable: runtime CPU feature detection
# rather than baking in whatever the build machine happened to support.
# CMAKE_INSTALL_LIBDIR is pinned to lib/ so the later COPY paths do not depend
# on whether GNUInstallDirs picks lib/ or lib64/ for this prefix.
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" \
	https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX=/usr/local \
	-DCMAKE_INSTALL_LIBDIR=lib \
	-DBUILD_SHARED_LIBS=ON \
	-DOQS_BUILD_ONLY_LIB=ON \
	-DOQS_DIST_BUILD=ON \
	-DOQS_ENABLE_KEM_BIKE=OFF \
	-DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
	-DOQS_ENABLE_KEM_FRODOKEM=OFF \
	-DOQS_ENABLE_KEM_HQC=ON \
	-DOQS_ENABLE_SIG_DILITHIUM=OFF \
	-DOQS_ENABLE_SIG_ML_DSA=OFF \
	-DOQS_ENABLE_SIG_FALCON=OFF \
	-DOQS_ENABLE_SIG_SPHINCS=OFF \
	-DOQS_ENABLE_SIG_MAYO=OFF \
	-DOQS_ENABLE_SIG_CROSS=OFF \
	-DOQS_ENABLE_SIG_UOV=OFF \
	-DOQS_ENABLE_SIG_STFL_LMS=OFF \
	-DOQS_ENABLE_SIG_STFL_XMSS=OFF \
    && cmake --build /tmp/liboqs/build --target install \
    && rm -rf /tmp/liboqs
# Stage what the later stages take, because `COPY --from` with a *wildcard*
# dereferences symlinks: COPY .../liboqs.so* would land liboqs.so, .so.9 and
# .so.0.16.0 as three identical 18M regular files. Copying a *directory*
# preserves links, so hand over prepared directories instead. cp -a keeps the
# links on this side. dev/ additionally carries the headers and the bare
# liboqs.so devel symlink, which a runtime image has no use for.
RUN mkdir -p /stage/dev/lib /stage/dev/include /stage/rt/lib \
    && cp -a /usr/local/lib/liboqs.so* /stage/dev/lib/ \
    && cp -a /usr/local/include/oqs /stage/dev/include/ \
    && cp -a /usr/local/lib/liboqs.so.* /stage/rt/lib/

FROM debian:${DEBIAN_TAG} AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
	gcc libc6-dev make libssl-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs /stage/dev/ /usr/local/
RUN ldconfig
WORKDIR /usr/src/libVES.c
COPY . .
RUN ./configure --with-oqs || (cat config.log; false)
RUN make
RUN make install DESTDIR=/out

# `docker build --target dev` produces a base for building other projects
# against libVES: toolchain, pkg-config, and both sets of headers (libVES's
# under /usr/include, liboqs's under /usr/local/include) with the devel
# symlinks the linker wants. Downstream builds just need `pkg-config --cflags
# --libs libVES`. This stage is not on the default target's dependency path,
# so a plain `docker build` skips it entirely.
FROM debian:${DEBIAN_TAG} AS dev
RUN apt-get update && apt-get install -y --no-install-recommends \
	gcc libc6-dev make pkg-config libssl-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs /stage/dev/ /usr/local/
COPY --from=build /out/ /
RUN ldconfig
CMD ["/bin/sh"]

FROM debian:${DEBIAN_TAG}
RUN apt-get update && apt-get install -y --no-install-recommends \
	libssl3 libcurl4 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs /stage/rt/ /usr/local/
COPY --from=build /out/ /
RUN ldconfig
ENTRYPOINT ["ves"]
CMD ["--help"]
