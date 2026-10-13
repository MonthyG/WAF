# Local development and recovery

The primary native targets are Ubuntu 24.04, AlmaLinux 9, and Debian 12 on x86-64. The application uses Node.js 24, pinned Go 1.26.9, and Docker Engine with Compose v2. Distro package-manager defaults often provide an older Node; do not use those defaults for this project. Windows users should use a Linux VM or Ubuntu under WSL2; macOS users should use a Linux VM for the full integration suite (the ACME test uses Linux host networking). Native Windows/macOS and ARM64 are not currently validated. This is a development environment, not a production installer.

## 1. Install prerequisites

Ubuntu 24.04 / Debian 12:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git make gcc libc6-dev python3 openssl tar gzip xz-utils
```

AlmaLinux 9:

```bash
sudo dnf install -y ca-certificates curl-minimal git make gcc glibc-devel python3 openssl tar gzip xz
```

If AlmaLinux already has the full `curl` package, omit `curl-minimal` from that command and keep the installed package; either variant supplies the required executable. Keep SELinux and firewalld enabled. The development Compose services bind only to loopback and use named volumes, avoiding checkout bind-mount labeling requirements. Container compatibility checks do not validate host SELinux policies.

Install Node 24 using your existing version manager. For a new nvm installation:

```bash
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh -o /tmp/waf-install-nvm.sh
bash /tmp/waf-install-nvm.sh
export NVM_DIR="$HOME/.nvm"
source "$NVM_DIR/nvm.sh"
nvm install 24
nvm alias default 24
nvm use 24
node --version
```

Install Docker Engine and the Compose plugin using the official instructions for [Ubuntu](https://docs.docker.com/engine/install/ubuntu/), [Debian](https://docs.docker.com/engine/install/debian/), or the [RHEL package family](https://docs.docker.com/engine/install/rhel/) for AlmaLinux. AlmaLinux is a compatible RHEL derivative, not an OS explicitly guaranteed by Docker's RHEL documentation. Use signed repositories and retain package signature verification. Do not install a second Docker daemon alongside an existing Snap/Desktop installation without first planning data preservation.

For a normal systemd Docker Engine installation:

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in, then check `docker info` and `docker compose version`. Docker group membership grants administrator-level access. Do not run npm or this project's setup under `sudo`.

### Existing Ubuntu Docker Snap

If `command -v docker` returns `/snap/bin/docker`, `docker.service` is not the correct service. Inspect `sudo snap services docker`, `id -nG`, and `ls -l /var/run/docker.sock`. If the group does not exist, create it and add the user:

```bash
sudo groupadd -f docker
sudo usermod -aG docker "$USER"
sudo snap disable docker
sudo snap enable docker
```

Disabling/re-enabling interrupts existing containers; plan that restart. Log out and log back in. Verify `docker ps` as your normal user before continuing. If the socket still belongs to `root:root`, inspect Snap's service logs (`sudo snap logs docker.dockerd`) and its daemon configuration; do not chmod the socket or fall back to running all development as root. Snap confinement can also affect the ACME test's temporary-file bind mounts. Docker Engine from the official package repository is the primary tested setup path; migrating away from Snap requires preserving its separate images, volumes, and settings first.

## 2. Prepare and start this checkout

From the repository root, as your normal user:

```bash
nvm use
bash scripts/setup.sh
source scripts/env.sh
npm ci
bash scripts/local-env.sh
npm run local:up
npm run doctor
npm run typecheck
npm run build
make test
npm test
```

Stop at any failing command. `local:up` loads `.local/dev.env`, checks Docker, starts services, tests actual PostgreSQL/ClickHouse authentication, and only then migrates the database. Root npm commands `db:migrate`, `test`, and `test:console` also load the local settings automatically, even in a new shell. Direct workspace commands remain available for CI/operator-managed environments.

A new checkout gets its own Compose project name and unused local ports. Re-running setup preserves all existing credentials and port choices. Port selection happens during configuration generation; if another process claims the chosen port later, startup reports the conflict. Existing installations keep their original project/ports so upgrades do not silently switch databases. Back up `.local/dev.env` securely together with the database; it contains encryption keys as well as passwords. Never commit or paste it.

For Chromium browser testing, use a real executable with its runtime dependencies installed. Debian provides `sudo apt-get install chromium`. Ubuntu's `chromium-browser` package is a Snap wrapper; set `CHROMIUM_PATH` to the actual executable you use. AlmaLinux may require an approved EPEL/browser repository. A browser installed by Playwright is another option, but Playwright's automatic OS dependency installer does not officially cover AlmaLinux. Browser availability is separate from WAF runtime support.

```bash
CHROMIUM_PATH=/path/to/chromium npm run test:console
```

This launches a temporary complete test stack and tests the dashboard; it does not leave a persistent demo login. For interactive proxy testing, use `make dev` and the curl requests in README.md. Real console startup still requires Keystone credentials as documented there.

## 3. Recover from the reported errors

| Symptom | Meaning and next action |
| --- | --- |
| `EBADENGINE`, Node 18 | Activate Node 24 and run `npm ci` again. `.nvmrc`, an engine check and strict npm engines now catch this early. |
| Docker socket permission denied | Fix daemon access as the normal user first; installing dependencies as root is not the remedy. |
| `docker.service` / group missing | Identify Snap, Desktop, or Engine installation before choosing service commands. |
| `18123 ... address already in use` | Another process/container owns the ClickHouse host port. Inspect `sudo ss -ltnp`; keep it running if it belongs to another application. |
| PostgreSQL `28P01` / password authentication failed | The server is reachable but its stored password differs from the local settings. Container health alone does not validate authentication. |
| Tests fail at `CREATE/DROP DATABASE` | Fix the database prerequisite before judging application tests. The test runner now checks authentication before starting fixtures. |

Deleting/re-cloning the Git directory does not remove Docker volumes. It can delete the matching `.local/dev.env` while retaining the database with its previous password. Restore the matching settings from backup if you need that data. A new password in Compose does not change an initialized PostgreSQL user's password. A lost master encryption key cannot be recovered by resetting the database password; encrypted certificate keys need the matching original key.

If this is a disposable local test and you want an **empty, separate installation while retaining the old one**, run:

```bash
npm run local:fresh
npm run local:up
npm run doctor
```

`local:fresh` saves existing settings under `.local/settings-backup.*/dev.env`, generates a unique project and free ports, and leaves every old container and volume untouched. It does not import old sites or recover lost keys. To return to the old installation, stop only the new project with `npm run local:stop`, preserve its settings, and restore the appropriate settings backup. Do not use `docker compose down -v` as an authentication fix.

To change a port in an existing installation, edit both the port and matching URL in `.local/dev.env`, then run `npm run local:up`:

| Compose variable | Matching application setting |
| --- | --- |
| `WAF_POSTGRES_PORT` | port inside `DATABASE_URL` |
| `WAF_CLICKHOUSE_PORT` | port inside `CLICKHOUSE_URL` |
| `WAF_REDIS_PORT` | port inside `REDIS_URL` |
| `WAF_NATS_PORT` | port inside `NATS_URL` |

If earlier root commands created root-owned checkout files, return to your normal user and repair ownership of that checkout only (`sudo chown -R "$(id -u):$(id -g)" "$HOME/WAF"` for the documented clone location). Then reactivate nvm and rerun `npm ci`. Never recursively change Docker's data-directory ownership.

## Compatibility validation

The GitHub Actions `Linux compatibility` workflow repeats build/Go tests and HTTP smoke tests for all three distributions on pushes and pull requests. Its remote run status is separate from local validation.

`scripts/compat/Dockerfile` builds the actual Go binaries and Next/API packages from source in pinned Ubuntu, AlmaLinux, and Debian userspaces. `scripts/compat/smoke.sh` sends real benign/XSS requests and requires 200/403 respectively. Reproduce, for example:

```bash
docker build -f scripts/compat/Dockerfile --build-arg DISTRO=ubuntu:24.04 -t waf-compat-ubuntu .
docker run --rm waf-compat-ubuntu
```

Use `almalinux:9` or `debian:12-slim` for the other distributions. The checked-in defaults pin image digests; mutable tags in the example intentionally test current distro images. See `docs/validation/platforms.json` for actual results and limits. Containers share the host kernel: these checks do not prove native VM installation, systemd, Snap, SELinux, ARM64, public TLS, or production readiness. `python3 scripts/test-local-setup.py` covers credential preservation, safe fresh starts, occupied-port selection, and rejection of Node 18.

AlmaLinux runtime validation can also reuse the verified Go/npm dependencies from the Debian test image when distro package mirrors are unavailable:

```bash
docker build -f scripts/compat/Dockerfile -t waf-compat-debian .
docker build -f scripts/compat/alma-runtime.Dockerfile -t waf-compat-alma-runtime .
docker run --rm waf-compat-alma-runtime
```

This rebuilds/tests Go with `CGO_ENABLED=0`, reinstalls npm packages from their integrity-checked cache, and rebuilds the API/console inside AlmaLinux; it does not test `dnf` installation or replace AlmaLinux's system libraries. The test images contain build caches and are deliberately large. Run matrix builds sequentially and allow roughly 40 GB free for the entire matrix, or remove only completed test images/cache before the next build. For a restricted HTTPS proxy, the Dockerfiles accept an optional BuildKit secret `trust_bundle` containing the approved CA bundle; forward proxy settings with Docker's standard build arguments and configure DNS resolution. Never turn off TLS or package verification.

`python3 scripts/test-local-lifecycle.py` is an optional Docker integration check. It creates a unique temporary stack, verifies authenticated startup and migrations twice, verifies that a bad password stops the test runner, then removes only the containers/volumes created by that test. It does not reset your development stack.
