# The coffre CLI's image, ghcr.io/erwinkn/coffre-cli: a release's
# @coffre/cli on Node 24, as a non-root user, for `coffre serve` (a
# workload's sidecar, docs/workloads.md) or any other command:
#
#   docker run --rm ghcr.io/erwinkn/coffre-cli:<version> --version
#
# The context is one file, coffre-cli.tgz. The release builds it from the
# tarball npm serves for the version, its integrity checked
# (.github/workflows/release.yml); Validate, from this revision's, packed as
# scripts/publish.sh packs it (scripts/test-image.sh). Nothing runs in the
# build, so each platform's image is its base and the same files, built
# without emulation.

# ADD unpacks the tarball, into /package.
FROM scratch AS cli
ADD coffre-cli.tgz /

# Distroless: Node and CA certificates, no shell and no package manager, so
# a process that took over the sidecar finds few tools. Its index's digest
# pins every platform's image.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8
# Owned by root: the user the CLI runs as cannot change it.
COPY --from=cli /package /usr/local/lib/node_modules/@coffre/cli
# dist/main.js starts with `#!/usr/bin/env node`, and there is no env here:
# `coffre` on PATH runs it with the image's Node, so a pod's
# `command: [coffre, …]` works as well as its `args`.
COPY --chmod=755 <<'EOF' /usr/local/bin/coffre
#!/nodejs/bin/node
import('/usr/local/lib/node_modules/@coffre/cli/dist/main.js');
EOF
# `node` too, for a probe's `node -e`.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/nodejs/bin
# The release adds the version and the revision it was built from.
LABEL org.opencontainers.image.title="coffre CLI" \
      org.opencontainers.image.description="The coffre command line; coffre serve is a workload's sidecar." \
      org.opencontainers.image.source="https://github.com/erwinkn/coffre" \
      org.opencontainers.image.licenses="MIT"
# nonroot, by number, as Kubernetes' runAsNonRoot needs.
USER 65532:65532
ENTRYPOINT ["coffre"]
