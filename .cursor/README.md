# Cursor

The Cloud Agent environment is defined in-repo by `.cursor/environment.json` and
`.cursor/Dockerfile` (Node 26.13.0 via nvm, pnpm 12.17.0's native executable from npm's tarball, and a Docker engine set
up for the nested VM). Two things worth knowing:

- **Docker and Postgres** come up each boot via `.cursor/start.sh`
  (`sudo service docker start`, then compose Postgres). PID 1 is tini, not
  systemd; the SysV script is what actually starts dockerd. Snapshot compose
  containers are dead until recreated. `/var/run` is not a symlink to `/run`
  here; snapshots and `service docker start` can leave it `0700`, so the
  script `chmod 755`s it *after* the daemon is up or `ubuntu` cannot see
  `docker.sock`. If `docker info` fails or `:55432` is down, re-run that
  script. Web and the dev IdP are started by `pnpm dev`, or by hand.
- **Node on PATH.** The Cloud runtime injects its own Node 22 ahead on `PATH`, so the
  image prepends the nvm-managed Node 26 in `~/.bashrc` (above the stock interactive-guard
  early return, since the runtime sources it for non-interactive shells too) and in
  `/etc/profile.d`. If `node -v` ever shows 22, that prepend did not run.
