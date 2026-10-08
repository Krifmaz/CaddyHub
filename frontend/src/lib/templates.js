// Starting points for common self-hosted apps. Only defaults: the user still
// sets the hostname and the upstream address.
const proxy = (upstream, extra = {}) => ({ kind: 'proxy', config: { proxy: { upstreams: [upstream], ...extra } } })

export const templates = [
  { id: 'vaultwarden', name: 'Vaultwarden', site: { ...proxy('vaultwarden:80', { websocket: true }), tags: ['security'] } },
  { id: 'jellyfin', name: 'Jellyfin', site: { ...proxy('jellyfin:8096', { websocket: true, flush_interval: '-1' }), tags: ['media'] } },
  { id: 'plex', name: 'Plex', site: { ...proxy('plex:32400', { websocket: true }), tags: ['media'] } },
  { id: 'immich', name: 'Immich', site: { kind: 'proxy', tags: ['media'], config: { proxy: { upstreams: ['immich-server:2283'], websocket: true }, max_body_size: '50GB' } } },
  { id: 'nextcloud', name: 'Nextcloud', site: { kind: 'proxy', tags: ['files'], config: { proxy: { upstreams: ['nextcloud:80'] }, max_body_size: '10GB', headers_set: { 'Strict-Transport-Security': 'max-age=31536000;' }, raw: 'redir /.well-known/carddav /remote.php/dav 301\nredir /.well-known/caldav /remote.php/dav 301' } } },
  { id: 'homeassistant', name: 'Home Assistant', site: { ...proxy('homeassistant:8123', { websocket: true }), tags: ['home'] } },
  { id: 'proxmox', name: 'Proxmox VE', site: { ...proxy('https://192.168.1.10:8006', { tls_skip_verify: true, websocket: true }), tags: ['infra'] } },
  { id: 'filebrowser', name: 'File Browser', site: { kind: 'proxy', tags: ['files'], config: { proxy: { upstreams: ['filebrowser:80'] }, max_body_size: '10GB' } } },
  { id: 'homepage', name: 'Homepage', site: { ...proxy('homepage:3000'), tags: ['dashboard'] } },
  { id: 'grafana', name: 'Grafana', site: { ...proxy('grafana:3000', { websocket: true }), tags: ['monitoring'] } },
  { id: 'static', name: 'Static website', site: { kind: 'static', config: { static: { root: '/srv/www' }, compression: ['zstd', 'gzip'] } } },
]
