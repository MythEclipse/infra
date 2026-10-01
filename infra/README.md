# Infra — Reverse Proxy & VPS Config

Config produksi untuk **orangevps** (Caddy reverse proxy + firewall + systemd drop-ins).

## Caddy (`caddy/`)

- `Caddyfile.prod` — **source of truth** untuk `/etc/caddy/Caddyfile`.
- Site pattern: `<service>.asepharyana.my.id` / `.web.id` → `import proxy <port>`.
- Auto-TLS Let's Encrypt; HTTP/3 default.
- Deploy: push `infra/caddy/**` ke `main` → workflow `caddy-deploy.yml` sync + reload + verify.

### Update site baru
```caddyfile
myservice.asepharyana.my.id {
	import proxy 4022
}
```
Commit + push → CI reload caddy → cek `curl -sI https://myservice.asepharyana.my.id`.

## Firewall (`firewall/`)

- `firewall.sh` — deny-by-default iptables:
  - Public: 22 (SSH), 80/443 (Caddy), 4013 (hermes dashboard), 25565 (Minecraft via TCPShield only)
  - Tailscale CGNAT `100.64.0.0/10`: semua port
  - Localhost: semua; sisanya DROP + logged.
- `99-hardening.conf`, `99-ssh-optimization.conf` — sysctl drop-ins.

## Prometheus (`prometheus/`)

- `targets.yml` — file_sd targets untuk Prometheus (node-exporter, app /metrics).

## systemd (`systemd/`)

- `scraper-otel.conf` — drop-in OTEL exporter untuk `scraper.service`.

## Deployment Model

Repo `asepharyana/infra` TIDAK build aplikasi. Aplikasi deploy via repo masing-masing
(`hub`, `scraper`, `mcpedia`) dengan `nix build → nix copy → nix-env --profile → systemctl restart`.
Repo ini hanya mengelola config yang di-sync manual/CI ke VPS.