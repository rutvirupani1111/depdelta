/**
 * Knowledge tables used by the analyzer. Keeping them in one place makes the
 * heuristics easy to review and to extend.
 */
import type { CapabilityKey } from '../types.js';

/** Node built-in modules that grant a capability (after stripping `node:` and subpaths). */
export const BUILTIN_MODULES: Record<string, CapabilityKey> = {
  fs: 'fs',
  'fs/promises': 'fs',
  net: 'network',
  tls: 'network',
  dgram: 'network',
  http: 'network',
  https: 'network',
  http2: 'network',
  dns: 'network',
  'dns/promises': 'network',
  child_process: 'child_process',
  cluster: 'child_process',
  worker_threads: 'worker_threads',
  vm: 'vm',
  os: 'os',
  crypto: 'crypto',
  module: 'module',
};

/** Well-known npm packages whose import implies a capability. */
export const THIRD_PARTY_MODULES: Record<string, CapabilityKey> = {
  axios: 'network',
  'node-fetch': 'network',
  got: 'network',
  undici: 'network',
  request: 'network',
  superagent: 'network',
  ws: 'network',
  'socket.io-client': 'network',
  'cross-fetch': 'network',
  'isomorphic-fetch': 'network',
  ky: 'network',
  needle: 'network',
  phin: 'network',
  'make-fetch-happen': 'network',
  'minipass-fetch': 'network',
  nodemailer: 'network',
  'basic-ftp': 'network',
  ssh2: 'network',
  execa: 'child_process',
  'cross-spawn': 'child_process',
  shelljs: 'child_process',
  'node-pty': 'child_process',
  zx: 'child_process',
};

/** Members of child_process (and friends) worth naming in findings. */
export const CHILD_PROCESS_METHODS = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'fork',
]);

export const NETWORK_METHODS = new Set([
  'request',
  'get',
  'connect',
  'createConnection',
  'createSocket',
  'lookup',
  'resolve',
  'resolve4',
  'resolve6',
  'resolveTxt',
  'createServer',
]);

export const OS_FINGERPRINT_METHODS = new Set([
  'homedir',
  'userInfo',
  'hostname',
  'networkInterfaces',
  'platform',
  'type',
  'release',
  'arch',
  'cpus',
  'tmpdir',
]);

/** Identifiers that refer to the global object. */
export const GLOBAL_OBJECTS = new Set(['globalThis', 'window', 'global', 'self', 'top', 'parent', 'frames']);

/** Global network APIs; overriding any of them is a hook on all traffic. */
export const NETWORK_GLOBALS = new Set([
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'Request',
  'Response',
  'Headers',
  'sendBeacon',
]);

/** Browser wallet providers injected by extensions. */
export const WALLET_GLOBALS = new Set([
  'ethereum',
  'solana',
  'phantom',
  'tronWeb',
  'tronLink',
  'okxwallet',
  'coinbaseWalletExtension',
  'BinanceChain',
  'web3',
  'keplr',
  'unisat',
  'bitkeep',
]);

/** Globals that change how code runs when replaced. */
export const EXEC_GLOBALS = new Set(['eval', 'Function', 'require', 'process', 'setTimeout', 'setInterval', 'importScripts']);

/** Constructors whose prototypes are shared by all code in the process. */
export const BUILTIN_CONSTRUCTORS = new Set([
  'Object',
  'Array',
  'Function',
  'String',
  'Number',
  'Boolean',
  'Symbol',
  'Promise',
  'RegExp',
  'Date',
  'Error',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'XMLHttpRequest',
  'WebSocket',
  'EventTarget',
  'Response',
  'Request',
  'Headers',
  'Buffer',
  'Uint8Array',
  'ArrayBuffer',
]);

/** Module-loader internals that let code intercept every `require`. */
export const LOADER_MEMBERS = new Set(['_load', '_resolveFilename', '_compile', '_extensions', 'require', 'wrap', '_findPath']);

/** Calls that decode data hidden in strings. */
export const DECODER_CALLS = new Set(['atob', 'unescape', 'decodeURIComponent', 'decodeURI']);

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

const SECRET_EXACT = new Set([
  'NPM_TOKEN',
  'NODE_AUTH_TOKEN',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'GITHUB_PAT',
  'GH_PAT',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CI_JOB_TOKEN',
  'GITLAB_TOKEN',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'DATABASE_URL',
  'MONGODB_URI',
  'MONGO_URL',
  'REDIS_URL',
  'SSH_AUTH_SOCK',
  'NPM_CONFIG__AUTH',
  'NPM_CONFIG__AUTHTOKEN',
]);

const AWS_BENIGN = new Set([
  'AWS_REGION',
  'AWS_DEFAULT_REGION',
  'AWS_PROFILE',
  'AWS_SDK_LOAD_CONFIG',
  'AWS_EXECUTION_ENV',
  'AWS_NODEJS_CONNECTION_REUSE_ENABLED',
  'AWS_XRAY_DAEMON_ADDRESS',
  'AWS_XRAY_CONTEXT_MISSING',
  'AWS_ENDPOINT_URL',
  'AWS_MAX_ATTEMPTS',
  'AWS_RETRY_MODE',
  'AWS_USE_FIPS_ENDPOINT',
  'AWS_USE_DUALSTACK_ENDPOINT',
]);

const SECRET_PATTERNS: RegExp[] = [
  /TOKEN/,
  /SECRET/,
  /PASSWORD|PASSWD/,
  /(^|_)(API|ACCESS|PRIVATE|SECRET|SIGNING|ENCRYPTION|MASTER|CLIENT|LICENSE|AUTH|SSH|GPG|DEPLOY)_?KEY(_|$)/,
  /(^|_)AUTH($|_)/,
  /CREDENTIAL/,
  /(^|_)PAT($|_)/,
  /COOKIE/,
  /SESSION_?(KEY|ID|TOKEN)/,
  /WEBHOOK/,
  /PRIVATE_KEY/,
  /MNEMONIC|SEED_PHRASE/,
];

/** True for environment variable names that usually hold credentials. */
export function isSecretEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  if (/^NPM_(PACKAGE|LIFECYCLE)_/.test(upper)) return false;
  if (SECRET_EXACT.has(upper)) return true;
  if (upper.startsWith('AWS_')) {
    if (AWS_BENIGN.has(upper) || upper.startsWith('AWS_LAMBDA_')) return false;
    return true;
  }
  if (upper.startsWith('AZURE_') && /(SECRET|KEY|TOKEN|PASSWORD|CONNECTION)/.test(upper)) return true;
  return SECRET_PATTERNS.some((re) => re.test(upper));
}

/** The most valuable tokens: registry, source-control and cloud credentials. */
export function isHighValueSecret(name: string): boolean {
  const upper = name.toUpperCase();
  return (
    /^(NPM_TOKEN|NODE_AUTH_TOKEN|NPM_CONFIG__AUTH.*|GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT|GITLAB_TOKEN|CI_JOB_TOKEN|ACTIONS_.*TOKEN.*)$/.test(
      upper,
    ) ||
    /^AWS_(SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)$/.test(upper) ||
    upper === 'GOOGLE_APPLICATION_CREDENTIALS' ||
    /^AZURE_CLIENT_SECRET$/.test(upper)
  );
}

// ---------------------------------------------------------------------------
// Network endpoints
// ---------------------------------------------------------------------------

export interface HostRule {
  label: string;
  /** Matches a host (lowercase, no port). */
  host: RegExp;
  /** Optional path prefix requirement. */
  path?: RegExp;
}

/** Endpoints commonly used to exfiltrate data or stage payloads. */
export const SUSPICIOUS_HOSTS: HostRule[] = [
  { label: 'Discord webhook', host: /(^|\.)(discord|discordapp)\.com$/, path: /^\/api\/(v\d+\/)?webhooks/i },
  { label: 'Telegram bot API', host: /^api\.telegram\.org$/ },
  { label: 'Slack webhook', host: /^hooks\.slack\.com$/ },
  { label: 'paste site', host: /(^|\.)(pastebin\.com|paste\.ee|pastebin\.pl|hastebin\.com|ghostbin\.\w+|rentry\.(co|org)|dpaste\.(com|org)|controlc\.com|justpaste\.it|paste\.rs|pastes\.dev)$/ },
  { label: 'ngrok tunnel', host: /(^|\.)ngrok(-free)?\.(io|app|dev)$|(^|\.)ngrok\.com$/ },
  { label: 'Cloudflare Workers', host: /\.workers\.dev$/ },
  { label: 'Cloudflare quick tunnel', host: /\.trycloudflare\.com$/ },
  { label: 'request inspector', host: /(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|hookbin\.com|beeceptor\.com|requestcatcher\.com|postb\.in|ptsv2\.com|ptsv3\.com)$/ },
  { label: 'out-of-band testing domain', host: /(^|\.)(burpcollaborator\.net|oastify\.com|interact\.sh|interactsh\.com|oast\.(pro|live|site|online|fun|me)|canarytokens\.(com|org)|dnslog\.cn|ceye\.io)$/ },
  { label: 'tunnel service', host: /(^|\.)(loca\.lt|localtunnel\.me|serveo\.net|bore\.pub|localhost\.run|pinggy\.(io|link)|tunnelmole\.net)$/ },
  { label: 'anonymous file drop', host: /(^|\.)(transfer\.sh|file\.io|0x0\.st|anonfiles\.com|gofile\.io|temp\.sh|catbox\.moe|litterbox\.catbox\.moe|ix\.io|termbin\.com|sprunge\.us|bashupload\.com|oshi\.at)$/ },
  { label: 'cloud metadata service', host: /^(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)$/ },
];

/** Hosts that are worth listing but not alarming on their own. */
export const NOTABLE_HOSTS: HostRule[] = [
  { label: 'raw code hosting', host: /^(raw\.githubusercontent\.com|gist\.githubusercontent\.com|gist\.github\.com|bitbucket\.org|gitlab\.com)$/ },
  { label: 'URL shortener', host: /^(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|goo\.gl|ow\.ly)$/ },
  { label: 'dynamic DNS', host: /(^|\.)(duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|sytes\.net|freedns\.afraid\.org)$/ },
];

/** Documentation, schema and spec hosts that show up in strings but are not endpoints. */
export const DOC_HOSTS =
  /(^|\.)(w3\.org|whatwg\.org|xmlsoap\.org|schemas\.microsoft\.com|schemas\.openxmlformats\.org|purl\.org|xmlns\.com|json-schema\.org|schema\.org|opensource\.org|spdx\.org|creativecommons\.org|ecma-international\.org|tc39\.es|developer\.mozilla\.org|mozilla\.org|nodejs\.org|npmjs\.(com|org)|npm\.im|github\.com|github\.io|githubusercontent\.com|githubassets\.com|stackoverflow\.com|wikipedia\.org|example\.(com|org|net)|ietf\.org|rfc-editor\.org|iana\.org|unicode\.org|chromium\.org|webkit\.org|microsoft\.com|apple\.com|google\.com|mdn\.io|caniuse\.com|semver\.org|yarnpkg\.com|pnpm\.io|typescriptlang\.org|babeljs\.io|eslint\.org|prettier\.io|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|opencollective\.com|tidelift\.com|sindresorhus\.com|feross\.org|reactjs\.org|react\.dev|vuejs\.org|angular\.io|jquery\.com|nextjs\.org|vercel\.com|apache\.org|gnu\.org|ogp\.me|gravatar\.com|shields\.io|badgen\.net|codecov\.io|coveralls\.io|travis-ci\.(org|com)|circleci\.com|readthedocs\.io|gitter\.im)$/;

/** Hosts that are never real endpoints. */
export const IGNORED_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|::1?|[\w.-]+\.(test|example|invalid|localhost|local))$/;

export function classifyHost(host: string, path = '/'): { kind: 'suspicious' | 'notable' | 'doc' | 'ignored' | 'other'; label?: string } {
  const h = host.toLowerCase().replace(/^www\./, '');
  if (IGNORED_HOSTS.test(h)) return { kind: 'ignored' };
  for (const rule of SUSPICIOUS_HOSTS) {
    if (rule.host.test(h) && (!rule.path || rule.path.test(path))) return { kind: 'suspicious', label: rule.label };
  }
  for (const rule of NOTABLE_HOSTS) {
    if (rule.host.test(h)) return { kind: 'notable', label: rule.label };
  }
  if (isPublicIp(h)) return { kind: 'notable', label: 'raw IP address' };
  if (DOC_HOSTS.test(h)) return { kind: 'doc' };
  return { kind: 'other' };
}

/** Substrings that mark exfiltration endpoints even when no full URL is present. */
export const SUSPICIOUS_FRAGMENTS: { label: string; re: RegExp }[] = [
  { label: 'Discord webhook', re: /(discord|discordapp)\.com\/api\/(v\d+\/)?webhooks/i },
  { label: 'Telegram bot API', re: /api\.telegram\.org\/bot/i },
  { label: 'Slack webhook', re: /hooks\.slack\.com\/services\//i },
  { label: 'request inspector', re: /\bwebhook\.site\b|\.m\.pipedream\.net\b|\brequestbin\.(com|net)\b/i },
  { label: 'ngrok tunnel', re: /\.ngrok(-free)?\.(io|app|dev)\b/i },
  { label: 'paste site', re: /\bpastebin\.com\/raw\b/i },
];

export function parseIpv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  if (m.slice(1).some((p) => p.length > 1 && p.startsWith('0'))) return null;
  return parts;
}

/** Public, routable IPv4 addresses (private, loopback, link-local, network and broadcast excluded). */
export function isPublicIp(s: string): boolean {
  const p = parseIpv4(s);
  if (!p) return false;
  const [a, b, , d] = p as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return s === '169.254.169.254';
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return s === '100.100.100.200';
  if (d === 0 || d === 255) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Crypto wallets
// ---------------------------------------------------------------------------

export const WALLET_PATTERNS: { label: string; re: RegExp }[] = [
  { label: 'Ethereum address', re: /^0x[a-fA-F0-9]{40}$/ },
  { label: 'Bitcoin address', re: /^(bc1|tb1)[02-9ac-hj-np-z]{11,71}$/ },
  { label: 'Bitcoin address', re: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/ },
  { label: 'Litecoin address', re: /^(ltc1[02-9ac-hj-np-z]{11,71}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})$/ },
  { label: 'Tron address', re: /^T[1-9A-HJ-NP-Za-km-z]{33}$/ },
];

const BENIGN_ETH = /^0x(0{40}|f{40}|e{40}|(ee){20})$/i;

/** Returns a wallet label when the whole string looks like a wallet address. */
export function walletLabel(s: string): string | undefined {
  if (s.length < 26 || s.length > 90) return undefined;
  for (const { label, re } of WALLET_PATTERNS) {
    if (!re.test(s)) continue;
    if (label === 'Ethereum address') {
      if (BENIGN_ETH.test(s)) return undefined;
      // A real address mixes letters and digits; filter repetitive constants.
      if (new Set(s.slice(2).toLowerCase()).size < 6) return undefined;
      return label;
    }
    if (/^(bc1|tb1|ltc1)/.test(s)) return label;
    // Base58 addresses: require a mix of upper, lower and digits to avoid matching words.
    const body = s.slice(1);
    if (/[A-Z]/.test(body) && /[a-z]/.test(body) && /\d/.test(body)) return label;
  }
  return undefined;
}

/** JSON-RPC methods and provider names used to talk to browser wallets. */
export const WALLET_RPC = /^(eth_sendTransaction|eth_signTransaction|eth_sign|eth_signTypedData(_v[34])?|eth_requestAccounts|eth_accounts|personal_sign|wallet_switchEthereumChain|wallet_addEthereumChain|solana_signTransaction|signAndSendTransaction)$/;

// ---------------------------------------------------------------------------
// Credentials, worms and droppers
// ---------------------------------------------------------------------------

export const CREDENTIAL_PATHS: { label: string; re: RegExp }[] = [
  { label: '.npmrc', re: /(^|[\\/~])\.npmrc\b/ },
  { label: '.yarnrc', re: /(^|[\\/~])\.yarnrc(\.yml)?\b/ },
  { label: 'SSH keys', re: /\.ssh([\\/]|$)|\bid_(rsa|ed25519|ecdsa|dsa)\b/ },
  { label: 'AWS credentials', re: /\.aws[\\/](credentials|config)\b/ },
  { label: 'git credentials', re: /\.git-credentials\b/ },
  { label: '.netrc', re: /(^|[\\/~])[._]netrc\b/ },
  { label: 'Docker credentials', re: /\.docker[\\/]config\.json/ },
  { label: 'Kubernetes config', re: /\.kube[\\/]config\b/ },
  { label: 'Google Cloud credentials', re: /gcloud[\\/](credentials\.db|application_default_credentials\.json|access_tokens\.db)|application_default_credentials\.json/ },
  { label: 'Azure credentials', re: /\.azure[\\/](accessTokens\.json|msal_token_cache)/ },
  { label: 'browser credential store', re: /\b(Login Data|Local State|Web Data)\b|Local Storage[\\/]leveldb/ },
  { label: 'crypto wallet files', re: /\bwallet\.dat\b|[\\/](Exodus|Electrum)[\\/]|\.electrum\b|nkbihfbeogaeaoehlefnkodbefgpgknn/ },
  { label: 'system password files', re: /^\/etc\/(passwd|shadow)$/ },
  { label: 'shell history', re: /\.(bash|zsh)_history\b/ },
  { label: 'GnuPG keyring', re: /\.gnupg([\\/]|$)/ },
  { label: 'secret scanner (trufflehog)', re: /\btrufflehog\b/i },
];

export const NPM_PUBLISH_PATTERNS: RegExp[] = [
  /\bnpm\s+(publish|whoami|token\s+(create|list)|adduser|owner\s+add|dist-tag\s+add)\b/,
  /\/-\/(whoami|npm\/v1\/tokens|user\/org\.couchdb\.user|v1\/search\?text=maintainer)/,
  /\bregistry\.npmjs\.org\/-\/(whoami|npm\/v1)/,
];

export const CI_TAMPER_PATTERNS: RegExp[] = [/\.github[\\/]workflows[\\/]?/, /\.gitlab-ci\.yml\b/, /\.circleci[\\/]config\.yml\b/];

/** Shell idioms that download or run remote code. */
export const SHELL_DOWNLOAD_PATTERNS: { label: string; re: RegExp }[] = [
  { label: 'curl', re: /\bcurl\s+(-[a-zA-Z]+\s+)*['"]?(https?:|ftp:|\$|`)/ },
  { label: 'wget', re: /\bwget\s+(-[a-zA-Z-]+\s+)*['"]?(https?:|ftp:|\$)/ },
  { label: 'pipe to shell', re: /\|\s*(sudo\s+)?(ba|z|da)?sh\b(\s|$)/ },
  { label: 'PowerShell download', re: /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|DownloadFile|Net\.WebClient)\b/i },
  { label: 'PowerShell eval', re: /\b(Invoke-Expression|iex)\b/i },
  { label: 'certutil download', re: /\bcertutil(\.exe)?\s+.*-urlcache/i },
  { label: 'bitsadmin download', re: /\bbitsadmin(\.exe)?\s+\/transfer/i },
  { label: 'reverse shell', re: /\/dev\/tcp\/|\bnc\s+(-e|-c)\b|\bncat\b.*-e\b|\bmkfifo\b/ },
  { label: 'base64 decode to shell', re: /base64\s+(-d|--decode)\s*\|/ },
];

/** Commands that are surprising to find shadowed by a package's `bin`. */
export const SYSTEM_COMMANDS = new Set([
  'node',
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'git',
  'sh',
  'bash',
  'zsh',
  'ls',
  'cd',
  'cp',
  'mv',
  'rm',
  'cat',
  'sudo',
  'su',
  'curl',
  'wget',
  'ssh',
  'scp',
  'python',
  'python3',
  'pip',
  'env',
  'which',
  'docker',
  'kubectl',
  'aws',
  'gh',
  'code',
  'open',
  'powershell',
  'pwsh',
  'cmd',
  'explorer',
]);

/** Install commands from well-known build tooling. */
export const KNOWN_INSTALL_TOOLS: RegExp =
  /^(node-gyp(-build)?|prebuild-install|node-pre-gyp|@mapbox\/node-pre-gyp|cmake-js|husky|patch-package|opencollective-postinstall|opencollective|is-ci|ngcc|electron-builder|napi-postinstall|node-gyp-build-optional-packages)\b/;

export const NATIVE_BUILD_TOOLS = /\b(node-gyp|prebuild-install|node-pre-gyp|cmake-js|node-gyp-build|napi-postinstall)\b/;

export const INSTALL_EVENTS = ['preinstall', 'install', 'postinstall', 'prepare'] as const;
