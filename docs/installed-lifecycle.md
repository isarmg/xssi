# Installed server lifecycle test

This gate tests a built release candidate through the real installer, systemd and product HTTP API. Run it on a disposable GitHub-hosted Linux runner with root and systemd.

## Run

Build the product's release binary and metadata with its pinned frontend builder. Check out XSSI at the revision in the product's `config/xssi.lock`. Both source checkouts must be clean.

For XSCS, create the candidate from that existing binary:

```sh
python3 -I -B "$XSSI/scripts/package-installed-candidate.py" xscs \
  "$SOURCE" "$BINARY" "$METADATA" "$OUTPUT"
```

Paths are absolute; OUTPUT is a new directory outside the checkouts. The command uses XSCS's release staging functions and the normal XSSI helper, SBOM and package-verification pipeline. It writes `xscs-VERSION-linux-x86_64.tar.gz` and `SHA256SUMS`.

Then run the lifecycle test on the same runner:

```sh
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  LIFECYCLE_DIAGNOSTICS="$RUNNER_TEMP/lifecycle-diagnostics" \
  python3 -I -B "$XSSI/tests/installed_lifecycle.py" \
  --adapter "$SOURCE/scripts/installed-lifecycle-adapter.py" \
  "$OUTPUT/xscs-VERSION-linux-x86_64.tar.gz" "$SOURCE_SHA"
```

SOURCE_SHA is the full product commit. Replace VERSION with the product version. Keep the candidate and its SHA256SUMS together.

## Product adapter

The small adapter lives in the product's tracked `scripts` directory and provides:

- `PRODUCT`, `ACCOUNT`, `SERVICES`: product name, service account and tuple of systemd units
- `RETAINED_FILES`: tuple of state-file paths relative to the installation root
- `configure(config, root, shared, port)`: configure production mode on loopback
- `exercise(request, session, sensitive, require)`: perform authenticated business operations and return expected state
- `persisted(request, session, state, require)`: check the same session and business state after restart
- `retained(root, shared, state, require)`: check additional retained files after uninstall

The harness supplies the HTTPS request helper and authenticated administrator session. Add any temporary business credentials to `sensitive` for diagnostic redaction. XSCS's adapter demonstrates device creation, renaming and authorization.

## Acceptance steps

1. Verify the archive and exact source identity.
2. Run the real installer and initialize an administrator with a temporary password.
3. Check service identity and read-only configuration permissions.
4. Start systemd services, log in over loopback HTTPS and exercise the product.
5. Restart services and verify session and business-data persistence.
6. Stop services and run the offline state check.
7. Remove the recorded unit registrations and runtime payload, verify retained data, then clean up temporary resources.

Successful stages print `PASS` lines in the job log. With LIFECYCLE_DIAGNOSTICS set, redacted diagnostics are written to `lifecycle.jsonl` in that directory. Upload only this diagnostic directory, never installed state or temporary credentials.

Run the shared regression tests with:

```sh
python3 -B -m unittest discover -s tests -p 'test_installed_*.py' -v
```

These regressions check the harness and candidate boundaries; the GitHub-hosted lifecycle job supplies the real installation result.
