// Piphin Rede · motor do Linux: responde os mesmos pedidos do engine.ps1 (mesmos campos), lendo /sys, /proc,
// o NetworkManager (nmcli) e o iproute2 (ip). Só lê: nada aqui muda a rede.
"use strict";
const fs = require("fs");
const os = require("os");
const dns = require("dns");
const dgram = require("dgram");
const { execFile } = require("child_process");

function run(file, args, { timeout = 20000 } = {}) {
  return new Promise((resolve) => {
    execFile(file, args, { timeout, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, LC_ALL: "C" } }, (err, out, errOut) =>
      resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, out: String(out || ""), err: String(errOut || "") }));
  });
}
const read = (f) => { try { return fs.readFileSync(f, "utf8").trim(); } catch { return ""; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// linhas do "nmcli -t" (campos separados por ":", com "\:" dentro dos valores)
function nmRows(out) {
  return out.split("\n").filter(Boolean).map((l) => {
    const f = []; let cur = "";
    for (let i = 0; i < l.length; i++) {
      if (l[i] === "\\" && i + 1 < l.length) { cur += l[++i]; continue; }
      if (l[i] === ":") { f.push(cur); cur = ""; continue; }
      cur += l[i];
    }
    f.push(cur);
    return f;
  });
}
// "nmcli -t device show": { "eth0": { "GENERAL.TYPE": "ethernet", "IP4.DNS[1]": "..." } }
async function nmDevices() {
  const r = await run("nmcli", ["-t", "device", "show"]);
  const out = {}; let cur = null;
  for (const line of r.out.split("\n")) {
    const i = line.indexOf(":"); if (i < 0) continue;
    const k = line.slice(0, i), v = line.slice(i + 1);
    if (k === "GENERAL.DEVICE") cur = out[v] = {};
    if (cur) cur[k] = v;
  }
  return out;
}

// --------------------------------------------------------------- placas de rede
const hex4 = (h) => [3, 2, 1, 0].map((i) => parseInt(h.substr(i * 2, 2), 16)).join(".");
function gateways4() {
  const by = {};
  for (const l of read("/proc/net/route").split("\n").slice(1)) {
    const f = l.trim().split(/\s+/);
    if (f.length > 7 && f[1] === "00000000" && f[2] !== "00000000") (by[f[0]] = by[f[0]] || []).push(hex4(f[2]));
  }
  return by;
}
function gateways6() {
  const by = {};
  for (const l of read("/proc/net/ipv6_route").split("\n")) {
    const f = l.trim().split(/\s+/);
    if (f.length < 10 || f[0] !== "0".repeat(32) || f[1] !== "00" || f[4] === "0".repeat(32)) continue;
    (by[f[9]] = by[f[9]] || []).push(f[4].match(/.{4}/g).join(":").replace(/(^|:)0{1,3}/g, "$1"));
  }
  return by;
}
async function info() {
  const nets = os.networkInterfaces(), g4 = gateways4(), g6 = gateways6(), nm = await nmDevices();
  const conn = (await run("nmcli", ["-t", "-f", "CONNECTIVITY", "general"])).out.trim();
  const adapters = [], profiles = [];
  let names = []; try { names = fs.readdirSync("/sys/class/net"); } catch { /* sem /sys */ }
  for (const name of names) {
    if (name === "lo") continue;
    const sys = `/sys/class/net/${name}`, d = nm[name] || {};
    const wireless = fs.existsSync(`${sys}/wireless`) || d["GENERAL.TYPE"] === "wifi";
    const virtual = !fs.existsSync(`${sys}/device`);
    const addrs = nets[name] || [];
    const speed = Number(read(`${sys}/speed`)) || 0; // Mb/s (cabo); no Wi-Fi vem da taxa do link
    const dnsList = Object.keys(d).filter((k) => /^IP[46]\.DNS\[/.test(k)).map((k) => d[k]);
    const description = [d["GENERAL.VENDOR"], d["GENERAL.PRODUCT"]].filter(Boolean).join(" ") || (virtual ? "Virtual " + name : name);
    adapters.push({
      id: name, name, description, type: wireless ? "Wireless80211" : virtual ? "Tunnel" : "Ethernet",
      up: read(`${sys}/operstate`) === "up" || (read(`${sys}/operstate`) === "unknown" && addrs.some((a) => a.family === "IPv4")),
      speed: speed > 0 ? speed * 1e6 : 0, mac: read(`${sys}/address`),
      ipv4: addrs.filter((a) => a.family === "IPv4").map((a) => ({ ip: a.address, prefix: Number(String(a.cidr || "").split("/")[1]) || 24 })),
      ipv6: addrs.filter((a) => a.family === "IPv6" && !/^fe80/i.test(a.address)).map((a) => a.address),
      gateways: g4[name] || [], gateways6: g6[name] || [], dns: dnsList,
      dhcp: Object.keys(d).some((k) => k.startsWith("DHCP4.OPTION")), mtu: Number(read(`${sys}/mtu`)) || 0,
    });
    if (d["GENERAL.CONNECTION"]) {
      // conectividade do NetworkManager no mesmo número que o Windows usa (4 = internet)
      const v = conn === "full" ? 4 : conn === "limited" || conn === "portal" ? 3 : conn === "none" ? 1 : 0;
      profiles.push({ alias: name, name: d["GENERAL.CONNECTION"], category: 0, v4: (g4[name] || []).length ? v : 0, v6: (g6[name] || []).length ? v : 0 });
    }
  }
  return { adapters, profiles };
}

// --------------------------------------------------------------- Wi-Fi
// números do Windows que o backend entende: Phy 7=Wi-Fi 4, 8=5, 10=6, 11=7; Auth (ver AUTH no backend)
const SEC_AUTH = (s) => (/802\.1X/i.test(s) ? (/WPA3/i.test(s) ? 8 : 6) : /WPA3|SAE/i.test(s) ? 9 : /WPA2/i.test(s) ? 7 : /WPA1|WPA/i.test(s) ? 4 : /WEP/i.test(s) ? 2 : /OWE/i.test(s) ? 10 : 1);
const SEC_NAME = (s) => (/802\.1X/i.test(s) ? "WPA2-Enterprise" : /WPA2/i.test(s) && /WPA3|SAE/i.test(s) ? "WPA2/WPA3" : /WPA3|SAE/i.test(s) ? "WPA3" : /OWE/i.test(s) ? "OWE"
  : /WPA2/i.test(s) ? "WPA2" : /WPA/i.test(s) ? "WPA" : /WEP/i.test(s) ? "WEP" : "open");
const chanOf = (mhz) => (mhz >= 5955 ? Math.round((mhz - 5950) / 5) : mhz >= 5000 ? Math.round((mhz - 5000) / 5) : mhz === 2484 ? 14 : Math.round((mhz - 2407) / 5));

function wifiIfaces() {
  let names = []; try { names = fs.readdirSync("/sys/class/net"); } catch { return []; }
  return names.filter((n) => fs.existsSync(`/sys/class/net/${n}/wireless`) || fs.existsSync(`/sys/class/net/${n}/phy80211`));
}
async function wifi() {
  const ifs = wifiIfaces();
  const interfaces = ifs.map((n) => ({ Guid: n, Description: n, State: read(`/sys/class/net/${n}/operstate`) === "up" ? 1 : 0 }));
  const connections = [];
  const list = nmRows((await run("nmcli", ["-t", "-f", "ACTIVE,SSID,BSSID,FREQ,SIGNAL,SECURITY,DEVICE", "device", "wifi", "list", "--rescan", "no"])).out);
  for (const n of ifs) {
    const act = list.find((f) => f[0] === "yes" && (!f[6] || f[6] === n));
    if (!act) continue;
    const link = (await run("iw", ["dev", n, "link"])).out; // sem o iw, fica sem taxa e padrão
    const rate = (re) => { const m = re.exec(link); return m ? Math.round(Number(m[1]) * 1000) : 0; };
    const tx = /tx bitrate:.*/.exec(link); const txl = tx ? tx[0] : "";
    const phy = /EHT-MCS/.test(txl) ? 11 : /HE-MCS/.test(txl) ? 10 : /VHT-MCS/.test(txl) ? 8 : /MCS/.test(txl) ? 7 : 0;
    const dbm = Number((/signal:\s*(-?\d+)/.exec(link) || [])[1]) || Math.round(Number(act[4]) / 2 - 100);
    const freq = Number(String(act[3]).replace(/\D/g, "")) || 0;
    connections.push({ Guid: n, State: 1, Profile: act[1], Ssid: act[1], Bssid: String(act[2]).toLowerCase(), Phy: phy, Signal: Number(act[4]) || 0,
      RxKbps: rate(/rx bitrate:\s*([\d.]+) MBit/), TxKbps: rate(/tx bitrate:\s*([\d.]+) MBit/), Secured: !!act[5] && act[5] !== "--", Auth: SEC_AUTH(act[5] || ""), Cipher: 0,
      Channel: chanOf(freq), Rssi: dbm });
  }
  return { interfaces, connections };
}
async function scan() { const r = await run("nmcli", ["device", "wifi", "rescan"]); return { code: r.code }; }
async function bss() {
  // BANDWIDTH só existe no NetworkManager 1.46 ou mais novo
  let r = await run("nmcli", ["-t", "-f", "SSID,BSSID,FREQ,SIGNAL,SECURITY,BANDWIDTH", "device", "wifi", "list", "--rescan", "no"]);
  const withWidth = r.code === 0;
  if (!withWidth) r = await run("nmcli", ["-t", "-f", "SSID,BSSID,FREQ,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "no"]);
  if (r.code !== 0) return { error: r.code, networks: [] };
  const seen = new Set(), networks = [];
  for (const f of nmRows(r.out)) {
    const bssid = String(f[1] || "").toLowerCase();
    if (!bssid || seen.has(bssid)) continue;
    seen.add(bssid);
    const q = Number(f[3]) || 0;
    networks.push({ Ssid: f[0], Bssid: bssid, Phy: 0, Rssi: Math.round(q / 2 - 100), Quality: q, FreqMhz: Number(String(f[2]).replace(/\D/g, "")) || 0,
      Width: withWidth ? Number(String(f[5]).replace(/\D/g, "")) || 20 : 20, Standard: "", Security: SEC_NAME(f[4] || "") });
  }
  return { error: 0, networks };
}

// --------------------------------------------------------------- uso da rede
function stats() {
  const list = [];
  for (const l of read("/proc/net/dev").split("\n").slice(2)) {
    const m = /^\s*([^:]+):\s*(.*)$/.exec(l); if (!m || m[1] === "lo") continue;
    const f = m[2].trim().split(/\s+/).map(Number);
    if (read(`/sys/class/net/${m[1]}/operstate`) === "down") continue;
    list.push({ id: m[1], rx: f[0], tx: f[8] });
  }
  return { at: Date.now(), list };
}

// programas usando a rede: sockets do /proc/net ligados aos processos pelos "socket:[inode]" (só os do próprio usuário)
function conns() {
  const sockets = new Map(); // inode -> { est, listen, udp, remote }
  const parse = (file, udp) => {
    for (const l of read(file).split("\n").slice(1)) {
      const f = l.trim().split(/\s+/); if (f.length < 10) continue;
      const st = f[3], inode = f[9], rem = f[2].split(":")[0];
      if (inode === "0") continue;
      // 0.0.0.0, 127.x (hex invertido termina em 7F), ::, ::1 e ::ffff:127.x
      const local = /^0+$/.test(rem) || /7F$/i.test(rem) && rem.length === 8 || rem === "00000000000000000000000001000000" || /^0000000000000000FFFF0000[0-9A-F]{6}7F$/i.test(rem);
      sockets.set(inode, { est: !udp && st === "01", listen: !udp && st === "0A", udp, remote: !udp && st === "01" && !local ? rem : null });
    }
  };
  parse("/proc/net/tcp", false); parse("/proc/net/tcp6", false); parse("/proc/net/udp", true); parse("/proc/net/udp6", true);
  const out = [];
  let pids = []; try { pids = fs.readdirSync("/proc").filter((d) => /^\d+$/.test(d)); } catch { /* sem /proc */ }
  for (const pid of pids) {
    let fds = []; try { fds = fs.readdirSync(`/proc/${pid}/fd`); } catch { continue; }
    const e = { pid: Number(pid), est: 0, listen: 0, udp: 0, remotes: new Set() };
    for (const fd of fds) {
      let t; try { t = fs.readlinkSync(`/proc/${pid}/fd/${fd}`); } catch { continue; }
      const m = /^socket:\[(\d+)\]$/.exec(t); if (!m) continue;
      const s = sockets.get(m[1]); if (!s) continue;
      if (s.est) e.est++; if (s.listen) e.listen++; if (s.udp) e.udp++; if (s.remote) e.remotes.add(s.remote);
    }
    if (!e.est && !e.listen && !e.udp) continue;
    let exe = ""; try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch { /* sem acesso */ }
    out.push({ pid: e.pid, name: read(`/proc/${pid}/comm`), desc: "", path: exe, est: e.est, listen: e.listen, udp: e.udp, remotes: e.remotes.size });
  }
  return { list: out };
}

// --------------------------------------------------------------- aparelhos da rede
async function neighbors() {
  const r = await run("ip", ["-j", "-4", "neigh"]);
  let rows = [];
  try { rows = JSON.parse(r.out).map((n) => ({ ip: n.dst, mac: n.lladdr, state: (n.state || [])[0] || "" })); }
  catch { // sem o ip -j: a tabela ARP do /proc
    rows = read("/proc/net/arp").split("\n").slice(1).map((l) => l.trim().split(/\s+/)).filter((f) => f.length >= 6).map((f) => ({ ip: f[0], mac: f[3], state: f[2] === "0x2" ? "REACHABLE" : "STALE" }));
  }
  const ST = { REACHABLE: "Reachable", STALE: "Stale", DELAY: "Delay", PROBE: "Probe", PERMANENT: "Permanent" };
  return { list: rows.filter((x) => x.mac && ST[x.state] && !/^(00:00:00:00:00:00|ff:ff:ff:ff:ff:ff|01:00:5e)/i.test(x.mac) && !/^(22[4-9]|23\d|255)\./.test(x.ip) && !/\.255$/.test(x.ip))
    .map((x) => ({ ip: x.ip, mac: x.mac.toLowerCase(), state: ST[x.state], ifIndex: 0 })) };
}
async function names(a) {
  const out = {};
  await Promise.all((a.ips || []).map((ip) => Promise.race([dns.promises.reverse(ip).then((n) => { if (n[0] && n[0] !== ip) out[ip] = n[0].replace(/\.$/, ""); }).catch(() => {}), sleep(2500)])));
  return out;
}

async function ask(cmd, a = {}) {
  switch (cmd) {
    case "wifi": return wifi();
    case "scan": return scan();
    case "bss": return bss();
    case "info": return info();
    case "stats": return stats();
    case "conns": return conns();
    case "neighbors": return neighbors();
    case "names": return names(a);
    case "do": return { jobs: [], mode: null }; // Otimização de Entrega só existe no Windows
    case "ping": return { pong: true };
    default: throw new Error("comando desconhecido: " + cmd);
  }
}

// --------------------------------------------------------------- testes
// "acorda" a rede local: um pacote UDP para cada endereço faz o sistema perguntar o MAC (ARP) de todos
async function sweep(base) {
  const s = dgram.createSocket("udp4");
  await new Promise((r) => s.bind(0, r));
  for (let i = 1; i <= 254; i++) s.send(Buffer.alloc(1), 9, `${base}.${i}`, () => {});
  await sleep(2500);
  s.close();
}
// ping do sistema (no Ubuntu funciona sem administrador): uma lista de ms por alvo, -1 quando não voltou
async function latency(ips, rounds) {
  const res = {};
  await Promise.all(ips.map(async (ip) => {
    const r = await run("ping", ["-n", "-c", String(rounds), "-i", "0.2", "-W", "1", ip], { timeout: rounds * 1500 + 5000 });
    const got = new Map();
    for (const m of r.out.matchAll(/icmp_seq=(\d+).*?time=([\d.]+)/g)) got.set(Number(m[1]), Math.round(Number(m[2])));
    res[ip] = Array.from({ length: rounds }, (_, i) => (got.has(i + 1) ? got.get(i + 1) : -1));
  }));
  return res;
}
// tempo de resposta de cada servidor DNS (sem cache: cada consulta vai direto ao servidor)
async function dnsBench(servers, hosts) {
  const out = {};
  for (const s of servers) {
    const r = new dns.promises.Resolver({ timeout: 2000, tries: 1 });
    r.setServers([s]);
    out[s] = [];
    for (const h of hosts) { const t = Date.now(); try { await r.resolve4(h); out[s].push(Date.now() - t); } catch { out[s].push(-1); } }
  }
  return out;
}

// ferramentas: limpar o cache de DNS (systemd-resolved) e renovar o IP (reconecta a conexão pelo NetworkManager)
async function flushDns() { const r = await run("resolvectl", ["flush-caches"]); return r.code === 0; }
async function renewIp(dev) {
  const d = (await nmDevices())[dev] || {};
  if (!d["GENERAL.CONNECTION"]) return false;
  return (await run("nmcli", ["connection", "up", "id", d["GENERAL.CONNECTION"]], { timeout: 90000 })).code === 0;
}
// telas de configuração (GNOME/Zorin; o editor de conexões do NetworkManager para as placas)
const SETTINGS = { network: ["gnome-control-center", ["network"]], wifi: ["gnome-control-center", ["wifi"]], location: ["gnome-control-center", ["privacy"]],
  update: ["update-manager", []], adapters: ["nm-connection-editor", []], reset: ["gnome-control-center", ["network"]] };
function openSettings(what) {
  const s = SETTINGS[what]; if (!s) return false;
  const { spawn } = require("child_process");
  spawn(s[0], s[1], { detached: true, stdio: "ignore" }).on("error", () => spawn("xdg-open", ["settings://"], { detached: true, stdio: "ignore" }).on("error", () => {}).unref()).unref();
  return true;
}

module.exports = { ask, sweep, latency, dnsBench, flushDns, renewIp, openSettings, nmRows, SEC_NAME, chanOf };
