# Releasing

1. Make sure `main` is green in CI.
2. Tag the release and push the tag:

   ```sh
   git tag -a v0.2.0 -m v0.2.0
   git push origin v0.2.0
   ```

3. The `release` workflow then:
   - runs the tests,
   - builds the image for linux/amd64 and linux/arm64 and pushes `ghcr.io/snigdhasambitak/istio-key-auth:<version>`
     and `:<major>.<minor>`,
   - packages the Helm chart with the tag as chart and app version, pushes it to
     `oci://ghcr.io/snigdhasambitak/charts`, and attaches it to a GitHub release with generated notes.

Versions follow semantic versioning. Before 1.0, a minor version may change flags or annotations; the release notes
say how to move.
