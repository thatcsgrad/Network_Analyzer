import subprocess
import socket
import time
import json
import sys
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] 'requests' not installed. Run: pip install requests")

TARGET_HOSTS = ["google.com", "cloudflare.com", "github.com"]
PING_COUNT = 5
RESULTS_FILE = "results.json"


def separator(title=""):
    line = "─" * 60
    if title:
        print(f"\n{line}\n  {title}\n{line}")
    else:
        print(line)


def get_public_ip():
    if not REQUESTS_OK:
        return "unavailable"
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5)
        return r.json().get("ip", "unknown")
    except Exception as e:
        return f"error: {e}"


def get_ip_info(ip):
    if not REQUESTS_OK:
        return {}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json()
    except Exception:
        return {}


def ping_host(host, count=PING_COUNT):
    param = "-n" if sys.platform.startswith("win") else "-c"
    cmd = ["ping", param, str(count), host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = result.stdout
        rtts = []
        for line in output.splitlines():
            if "time=" in line:
                try:
                    rtt = float(line.split("time=")[1].split()[0].rstrip("ms"))
                    rtts.append(rtt)
                except (IndexError, ValueError):
                    pass
            elif "time" in line and "ms" in line and "Reply" in line:
                try:
                    rtt = float(line.split("time")[1].split("ms")[0].strip("=<"))
                    rtts.append(rtt)
                except (IndexError, ValueError):
                    pass
        if rtts:
            return {
                "host": host,
                "sent": count,
                "received": len(rtts),
                "loss_pct": round((count - len(rtts)) / count * 100, 1),
                "min_ms": round(min(rtts), 2),
                "avg_ms": round(sum(rtts) / len(rtts), 2),
                "max_ms": round(max(rtts), 2),
                "jitter_ms": round(max(rtts) - min(rtts), 2),
            }
        else:
            return {"host": host, "error": "no RTT values parsed", "raw": output[:200]}
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "timeout"}
    except Exception as e:
        return {"host": host, "error": str(e)}


def resolve_dns(hostname):
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = list({r[4][0] for r in results})
        return {"hostname": hostname, "resolved_ips": ips, "count": len(ips)}
    except socket.gaierror as e:
        return {"hostname": hostname, "error": str(e)}


def check_dns_leak():
    if not REQUESTS_OK:
        return {"note": "install requests to enable DNS leak check"}
    try:
        r = requests.get("https://bash.ws/dnsleak/test/random?json", timeout=8)
        data = r.json()
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = data.get("servers", data.get("results", [data]))
        else:
            entries = []
        servers = []
        countries = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip") or entry.get("server")
            country = entry.get("country_name") or entry.get("country")
            if ip:
                servers.append(ip)
            if country:
                countries.append(country)
        countries = list(set(countries))
        if servers:
            return {
                "dns_servers_detected": servers[:5],
                "countries": countries,
                "possible_leak": len(countries) > 1,
                "method": "bash.ws",
            }
    except Exception:
        pass
    try:
        r = requests.get("https://ipinfo.io/json", timeout=6)
        info = r.json()
        return {
            "dns_servers_detected": [info.get("ip", "unknown")],
            "countries": [info.get("country", "unknown")],
            "possible_leak": False,
            "method": "ipinfo fallback",
            "note": "Full DNS leak test unavailable. Showing exit IP only.",
        }
    except Exception as e:
        return {"error": str(e), "note": "DNS leak check failed"}


def measure_http_latency(url="https://www.google.com"):
    if not REQUESTS_OK:
        return {"error": "requests not installed"}
    try:
        t0 = time.time()
        r = requests.get(url, timeout=10)
        elapsed = round((time.time() - t0) * 1000, 2)
        return {
            "url": url,
            "status_code": r.status_code,
            "response_ms": elapsed,
            "content_bytes": len(r.content),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def run_analysis(label):
    separator(f"Running analysis: {label.upper().replace('_', ' ')}")
    results = {"label": label, "timestamp": datetime.now().isoformat()}

    print("\n[1] Checking public IP address...")
    pub_ip = get_public_ip()
    ip_info = get_ip_info(pub_ip) if pub_ip and "error" not in pub_ip else {}
    results["public_ip"] = {
        "ip": pub_ip,
        "city": ip_info.get("city", "unknown"),
        "region": ip_info.get("region", "unknown"),
        "country": ip_info.get("country", "unknown"),
        "org": ip_info.get("org", "unknown"),
    }
    print(f"    IP      : {pub_ip}")
    print(f"    Location: {ip_info.get('city', '?')}, {ip_info.get('country', '?')}")
    print(f"    ISP/Org : {ip_info.get('org', '?')}")

    print("\n[2] Measuring latency via ICMP ping...")
    ping_results = []
    for host in TARGET_HOSTS:
        r = ping_host(host)
        ping_results.append(r)
        if "error" not in r:
            print(f"    {host:<22} avg={r['avg_ms']}ms  jitter={r['jitter_ms']}ms  loss={r['loss_pct']}%")
        else:
            print(f"    {host:<22} ERROR: {r['error']}")
    results["ping"] = ping_results

    print("\n[3] DNS resolution check...")
    dns_results = []
    for host in TARGET_HOSTS:
        r = resolve_dns(host)
        dns_results.append(r)
        if "error" not in r:
            print(f"    {host:<22} resolved to {r['count']} IP(s): {r['resolved_ips'][:2]}")
        else:
            print(f"    {host:<22} ERROR: {r['error']}")
    results["dns_resolution"] = dns_results

    print("\n[4] DNS leak test...")
    leak = check_dns_leak()
    results["dns_leak"] = leak
    if "error" not in leak:
        print(f"    DNS servers seen : {leak.get('dns_servers_detected', [])}")
        print(f"    Countries        : {leak.get('countries', [])}")
        print(f"    Possible leak?   : {leak.get('possible_leak', '?')}")
    else:
        print(f"    {leak}")

    print("\n[5] HTTP response latency...")
    http_r = measure_http_latency()
    results["http_latency"] = http_r
    if "error" not in http_r:
        print(f"    google.com responded in {http_r['response_ms']} ms ({http_r['content_bytes']} bytes)")
    else:
        print(f"    ERROR: {http_r['error']}")

    return results


def compare_results(r1, r2):
    separator("COMPARISON: Without VPN  vs  With VPN")
    ip1 = r1["public_ip"]["ip"]
    ip2 = r2["public_ip"]["ip"]
    print(f"\n{'Metric':<28} {'Without VPN':<28} {'With VPN'}")
    print("─" * 75)
    print(f"{'Public IP':<28} {ip1:<28} {ip2}")
    print(f"{'Location':<28} {r1['public_ip']['city']+', '+r1['public_ip']['country']:<28} {r2['public_ip']['city']+', '+r2['public_ip']['country']}")
    print(f"{'ISP/Org':<28} {str(r1['public_ip']['org'])[:26]:<28} {str(r2['public_ip']['org'])[:26]}")

    print()
    for p1, p2 in zip(r1["ping"], r2["ping"]):
        if "error" not in p1 and "error" not in p2:
            diff = round(p2["avg_ms"] - p1["avg_ms"], 2)
            sign = "+" if diff >= 0 else ""
            print(f"  Ping avg {p1['host']:<20} {p1['avg_ms']:<6} ms          {p2['avg_ms']:<6} ms   ({sign}{diff} ms overhead)")

    h1 = r1.get("http_latency", {})
    h2 = r2.get("http_latency", {})
    if "response_ms" in h1 and "response_ms" in h2:
        diff = round(h2["response_ms"] - h1["response_ms"], 2)
        sign = "+" if diff >= 0 else ""
        print(f"\n  HTTP latency (google.com)    {h1['response_ms']:<10} ms    {h2['response_ms']:<10} ms  ({sign}{diff} ms)")

    l1 = r1.get("dns_leak", {})
    l2 = r2.get("dns_leak", {})
    print(f"\n  DNS leak detected?           {'Yes' if l1.get('possible_leak') else 'No':<28} {'Yes' if l2.get('possible_leak') else 'No'}")

    separator()
    print("\n  Key Observations:")
    if ip1 != ip2:
        print("  ✓ VPN successfully masks your real IP address.")
    else:
        print("  ✗ IP address unchanged — VPN may not be active.")

    all_p1 = [p["avg_ms"] for p in r1["ping"] if "avg_ms" in p]
    all_p2 = [p["avg_ms"] for p in r2["ping"] if "avg_ms" in p]
    if all_p1 and all_p2:
        avg_overhead = round(sum(all_p2) / len(all_p2) - sum(all_p1) / len(all_p1), 2)
        print(f"  ✓ Average VPN latency overhead: {avg_overhead} ms across {len(all_p1)} hosts.")

    if l2.get("possible_leak"):
        print("  ⚠ DNS leak detected with VPN — queries may expose your real ISP.")
    else:
        print("  ✓ No DNS leak detected with VPN active.")


def save_results(r1, r2):
    data = {
        "analysis_date": datetime.now().isoformat(),
        "without_vpn": r1,
        "with_vpn": r2,
    }
    with open(RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  Results saved → {RESULTS_FILE}")


def main():
    print("\n" + "═" * 60)
    print("   VPN Network Analyser — Privacy & Performance Tool")
    print("   Author: Sanika Rane")
    print("═" * 60)
    print("""
This tool measures how a VPN affects:
  • Your visible IP address and geographic location
  • Network latency (ping) to common servers
  • DNS resolution behaviour
  • Potential DNS leaks
  • HTTP response times

INSTRUCTIONS
─────────────────────────────────────────────────────
Step 1 : Make sure your VPN is OFF, then press Enter.
Step 2 : The tool will run the first analysis.
Step 3 : Turn your VPN ON, then press Enter.
Step 4 : The tool will run the second analysis.
Step 5 : A side-by-side comparison will be printed.
─────────────────────────────────────────────────────
""")
    input("  [Press Enter to start — make sure VPN is OFF] ")
    results_no_vpn = run_analysis("without_vpn")

    print("\n" + "─" * 60)
    input("  [Now turn your VPN ON, then press Enter] ")
    results_vpn = run_analysis("with_vpn")

    compare_results(results_no_vpn, results_vpn)
    save_results(results_no_vpn, results_vpn)
    print("\n  Done! Check results.json for the full data.\n")


if __name__ == "__main__":
    main()
