import requests
import socket
import dns.resolver
import argparse
import json
import threading
import itertools
import time
import sys
from scapy.all import sniff, DNS, DNSRR

# Known takeover patterns
takeover_signatures = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "amazonaws.com": "The specified bucket does not exist",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "pantheon.io": "404 error unknown site!",
    "fastly.net": "Fastly error: unknown domain",
    "cloudfront.net": "The request could not be satisfied",
    "azurewebsites.net": "404 Web Site not found",
    "windows.net": "No web site is configured",
    "readthedocs.io": "unknown to Read the Docs",
    "wpengine.com": "The site you were looking for couldn't be found.",
    "zendesk.com": "Help Center Closed",
    "helpscoutdocs.com": "We could not find what you're looking for.",
    "desk.com": "Please try again or contact support",
    "statuspage.io": "There is no status page configured",
    "smartling.com": "Domain is not configured",
    "unbouncepages.com": "The requested URL was not found on this server",
    "tumblr.com": "There's nothing here.",
    "cargo.site": "404 Not Found",
    "cargocollective.com": "Non-Existent Domain",
    "simplebooklet.com": "We can't find that page",
    "launchrock.com": "It looks like you may have taken a wrong turn",
    "cloudapp.net": "The resource you are looking for has been removed",
    "storenvy.com": "Page Not Found",
    "myshopify.com": "Sorry, this shop is currently unavailable.",
    "shopify.com": "Couldn't find the page you're looking for",
    "githubusercontent.com": "404 Not Found",
    "teamwork.com": "Oops - Looks like this page doesn't exist.",
    "hatenablog.com": "404 Blog is not found",
    "strikinglydns.com": "Page not found",
    "wordpress.com": "Do you want to register",
    "ghost.io": "404",
    "blogspot.com": "404. That’s an error.",
    "firebaseapp.com": "404 Not Found",
    "webflow.io": "The page you are looking for doesn't exist",
    "kayako.com": "Help Desk Not Found",
    "domain.market": "is available for purchase",
    "launchdarkly.com": "This page is not available",
    "acquia-sites.com": "This site is not available",
    "herokussl.com": "No such app",
    "herokudns.com": "No such app",
    "intercom.io": "Uh oh, we couldn't find the page you're looking for",
    "uservoice.com": "This UserVoice subdomain is currently available!",
    "getsatisfaction.com": "company not found",
    "aftership.com": "Oops. The page you were looking for doesn't exist.",
    "vendhq.com": "Oops! Looks like you tried to visit a page that doesn't exist",
    "tictail.com": "No such store",
    "bigcartel.com": "Oops! We couldn’t find that page.",
    "jive.com": "Page Not Found",
    "brightcovegallery.com": "404: Page not found",
    "createsend.com": "Oops! Something went wrong",
    "helpscout.net": "We couldn't find the page you're looking for",
    "intercom.com": "Uh oh, we couldn't find the page you're looking for"
}


results = []
spinner_running = False


def banner():
    print("=" * 40)
    print("||\t\t~ GhostDNS ~ \t\t||")
    print("||\tSubdomain Takeover Scanner \t||")
    print("=" * 40)


def load_wordlist(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines()]


def resolve_subdomain(sub, root_domain):
    domain = f"{sub}.{root_domain}"
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            return domain, "CNAME", str(rdata.target)
    except:
        try:
            ip = socket.gethostbyname(domain)
            return domain, "A", ip
        except:
            return None


def check_http(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        for keyword, signature in takeover_signatures.items():
            if signature in r.text:
                return True, keyword
    except:
        pass
    return False, None


def find_takeovers(domain, wordlist_path, output_path):
    subs = load_wordlist(wordlist_path)
    print(f"[i] Checking {len(subs)} subdomains of {domain}\n")
    for sub in subs:
        handle_result(sub, domain, output_path)


def handle_result(sub, domain, output_path):
    result = resolve_subdomain(sub, domain)
    if result:
        name, rtype, target = result
        print(f"[+] {name} -> ({rtype}) {target}")
        for keyword in takeover_signatures:
            if keyword in target:
                vulnerable, service = check_http(name)
                if vulnerable:
                    print(
                        f"[!!] Possible takeover: {name} pointing to {service}")
                    store_result(name, rtype, target,
                                 service, "Possible Takeover")
                    return
        store_result(name, rtype, target, None, "No Issue")


def store_result(name, rtype, target, service, status):
    results.append({
        "subdomain": name,
        "type": rtype,
        "target": target,
        "service": service if service else "",
        "status": status
    })


def dns_sniffer(domain_filter, output_path, timeout=60):
    def process_packet(packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            dns_layer = packet[DNS]
            qname = dns_layer.qd.qname.decode().strip(".")
            if domain_filter in qname:
                print(f"\n[DNS] Response for: {qname}")
                print(
                    f"↳ Query Type: {dns_layer.qd.qtype}, Answers: {dns_layer.ancount}, TTL: {dns_layer.qd.qclass}")
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an[i]
                    if rr.type == 1:
                        print(
                            f"  A Record: {rr.rrname.decode()} -> {rr.rdata}")
                    elif rr.type == 5:
                        print(
                            f"  CNAME: {rr.rrname.decode()} -> {rr.rdata.decode()}")
                    elif rr.type == 2:
                        print(
                            f"  NS: {rr.rrname.decode()} -> {rr.rdata.decode()}")
                    elif rr.type == 16:
                        print(
                            f"  TXT: {rr.rrname.decode()} -> {rr.rdata.decode()}")
                sub = qname.replace(f".{domain_filter}", "")
                handle_result(sub, domain_filter, output_path)

    print("[i] Listening for DNS responses... (Auto-stop in", timeout, "seconds)")
    try:
        sniff(filter="udp port 53", prn=process_packet,
              store=False, timeout=timeout)
    except KeyboardInterrupt:
        print("\n[i] Sniffing stopped.")


def spinner():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if not spinner_running:
            break
        sys.stdout.write('\rScanning... ' + c)
        sys.stdout.flush()
        time.sleep(0.1)


def main():
    global spinner_running
    parser = argparse.ArgumentParser(
        description="GhostDNS - Subdomain Takeover Detection Tool")
    parser.add_argument("-d", "--domain", required=True,
                        help="Target root domain")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument(
        "-o", "--output", help="Path to output JSON file (optional)")
    parser.add_argument("--sniff", action="store_true",
                        help="Enable DNS sniffing mode")
    parser.add_argument("--timeout", type=int,
                        help="Timeout for DNS sniffing (in seconds)")
    args = parser.parse_args()

    banner()

    if args.sniff:
        timeout = args.timeout or 60
        dns_sniffer(args.domain, args.output, timeout=timeout)
    else:
        spinner_running = True
        spin_thread = threading.Thread(target=spinner)
        spin_thread.start()

        find_takeovers(args.domain, args.wordlist, args.output)

        spinner_running = False
        spin_thread.join()
        print("\n[i] Scan complete.")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[✓] Results saved to {args.output}")


if __name__ == "__main__":
    main()
