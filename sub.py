#!/usr/bin/env python3
import os
import sys
import time
import random
import signal
import tempfile
import subprocess
from termcolor import colored
WORDLIST="/home/boot/Desktop/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
resolvers="./resolvers.txt"

# Import api_keys module (assuming it exists with the necessary lists/dicts)
import api_keys

# Signal handler for CTRL+C
def signal_handler(sig, frame):
    print(colored("\n[!] Script interrupted by user (CTRL+C). Exiting...", 'red'))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Color functions
def red(text): return colored(text, 'red')
def green(text): return colored(text, 'green')
def yellow(text): return colored(text, 'yellow')
def blue(text): return colored(text, 'blue')
def cyan(text): return colored(text, 'cyan')
def magenta(text): return colored(text, 'magenta')

# Failed tools set (to skip previously failed tools)
failed_tools = set()

def is_tool_failed(name):
    return name in failed_tools

def mark_tool_failed(name):
    failed_tools.add(name)

# Banner
print(cyan("""
╔═══════════════════════════════════════════════════════════╗
║ ADVANCED SUBDOMAIN ENUMERATION FRAMEWORK v2.0 ║
║ Multi-Domain | Multi-Tool | Verbose ║
╚═══════════════════════════════════════════════════════════╝
"""))

# Check if domains.txt exists
if not os.path.exists("domains.txt"):
    print(red("[!] CRITICAL ERROR: domains.txt not found!"))
    print(yellow("[*] Please create a domains.txt file with one domain per line"))
    print(blue(" echo 'example.com' > domains.txt"))
    print(blue(" echo 'target.com' >> domains.txt"))
    sys.exit(1)

# Read domains
with open("domains.txt") as f:
    domains = [line.strip() for line in f if line.strip()]

print(green("[✓] Successfully loaded domains.txt"))
print(cyan(f"[*] Total domains to scan: {len(domains)}"))
print(cyan(f"[*] Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}"))
print("")

# Create temporary file for all subdomains
temp_file = tempfile.NamedTemporaryFile(delete=False).name

# Tool functions (each tool is a separate function for easy addition/removal/editing)
# To add a new tool: Define a new def run_newtool(domain, temp_file): ... and add to tool_funcs list below.
# To remove a tool: Remove the function and remove it from tool_funcs list.
# Editing a tool won't affect others since each is isolated.

def run_dnsx(domain, temp_file):
    name = 'dnsx'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"dnsx -d '{domain}' -silent 2>/dev/null | awk '{{print $1}}' | sed 's/\\.$//' | grep '{domain}' | sort -u"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
        mark_tool_failed(name)
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))
        mark_tool_failed(name)

def run_cero(domain, temp_file):
    name = 'cero'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"cero '{domain}' 2>/dev/null | grep -oP 'https?://\\K[^/]+' | grep '{domain}' | sort -u"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
        mark_tool_failed(name)
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))
        mark_tool_failed(name)

def run_altdns(domain, temp_file):
    name = 'altdns'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    try:
        # Create temp input
        with open('altdns_input.tmp', 'w') as f:
            f.write(domain + '\n')

        # هنا نستخدم WORDLIST الحقيقي
        subprocess.check_output(
            f"altdns -i altdns_input.tmp -o altdns_output.tmp -w {WORDLIST} 2>/dev/null",
            shell=True
        )

        command = f"massdns -r {resolvers} -t A -o S altdns_output.tmp 2>/dev/null | awk '{{print $1}}' | sed 's/\\.$//' | grep '{domain}' | sort -u"
        output = subprocess.check_output(command, shell=True, timeout=120)

        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")

        os.remove('altdns_input.tmp')
        os.remove('altdns_output.tmp')
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))

    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
        mark_tool_failed(name)

    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))
        mark_tool_failed(name)

    finally:
        if os.path.exists('altdns_input.tmp'):
            os.remove('altdns_input.tmp')
        if os.path.exists('altdns_output.tmp'):
            os.remove('altdns_output.tmp')


def run_massdns(domain, temp_file):
    name = 'massdns'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"massdns -r {resolvers} -t A -o S {WORDLIST} 2>/dev/null | grep -oP '^[^ ]+' | grep '{domain}' | sort -u"
    try:
        output = subprocess.check_output(command, shell=True, timeout=90)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
        mark_tool_failed(name)
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))
        mark_tool_failed(name)

def run_findomain2(domain, temp_file):
    name = 'findomain2'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"findomain -t '{domain}' -q 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
        mark_tool_failed(name)
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))
        mark_tool_failed(name)

import subprocess
import time

import subprocess
import time

def run_dnsbuster(domain, temp_file):
    name = 'dnsbuster'
    if is_tool_failed(name):
        print(red(f"[X] {name} - SKIPPED (Previously failed)"))
        return

    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()

    command = f"dnsbuster -d {domain} -w {WORDLIST} -r {resolvers} 2>/dev/null"

    # طباعة الأمر الذي سيتم تنفيذه
    print(f"Running command: {command}")

    try:
        output = subprocess.check_output(command, shell=True, timeout=120, stderr=subprocess.STDOUT)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")

        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))

    except subprocess.TimeoutExpired as e:
        print(red(f"[✗] {name} timed out"))
        print(e.output)  # طباعة مخرجات الخطأ
        mark_tool_failed(name)

    except subprocess.CalledProcessError as e:
        print(red(f"[✗] {name} failed (Execution error)"))
        print(e.output)  # طباعة مخرجات الخطأ
        mark_tool_failed(name)

        
def run_fofa(domain, temp_file):
    name = 'fofa'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    fofa_email = random.choice(api_keys.FOFA_EMAIL)
    fofa_key = random.choice(api_keys.FOFA_KEY)
    # Placeholder command (replace with actual API call if available)
    command = "echo 'fofa_results_here.com'"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
            f.write(f"FOFA_EMAIL={fofa_email}\n".encode())
            f.write(f"FOFA_KEY={fofa_key}\n".encode())
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_subfinder(domain, temp_file):
    name = 'subfinder'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"subfinder -d '{domain}' -all -silent 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=122)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_assetfinder(domain, temp_file):
    name = 'assetfinder'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"assetfinder --subs-only '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=120)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))



def run_shuffledns(domain, temp_file):
    name = 'shuffledns'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    # Placeholder command (replace with actual if available)
    command = "echo 'shuffledns-result-example.com'"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_findomain(domain, temp_file):
    name = 'findomain'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"findomain -t '{domain}' -q 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=120)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_gau(domain, temp_file):
    name = 'gau'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"gau '{domain}' 2>/dev/null | grep '{domain}' | awk -F/ '{{print $3}}' | sort -u"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_crtsh(domain, temp_file):
    name = 'crtsh'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' | sort -u"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_github_subdomains(domain, temp_file):
    name = 'github-subdomains'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    github_token = random.choice(api_keys.GITHUB_TOKENS)
    command = f"github-subdomains -d '{domain}' -t '{github_token}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_chaos(domain, temp_file):
    name = 'chaos'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    chaos_key = random.choice(api_keys.CHAOS_API_KEY)
    command = f"chaos -key '{chaos_key}' -d '{domain}' -silent 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_sublist3r(domain, temp_file):
    name = 'sublist3r'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"sublist3r -d '{domain}' -o /dev/stdout 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=120)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_shodan(domain, temp_file):
    name = 'shodan'
    shodan_api_key = random.choice(api_keys.SHODAN_API_KEY)
    if not shodan_api_key:
        print(red(f"[X] {name} - SKIPPED (No API keys found)"))
        return
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"shosubgo -d '{domain}' -s '{shodan_api_key}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_gitlab_subdomains(domain, temp_file):
    name = 'gitlab-subdomains'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    gitlab_token = random.choice(api_keys.GITLAB_TOKENS)
    command = f"gitlab-subdomains -d '{domain}' -t '{gitlab_token}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=120)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_securitytrails(domain, temp_file):
    name = 'securitytrails'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    securitytrails_key = random.choice(api_keys.SECURITYTRAILS_KEYS)
    # Placeholder command (replace with actual API call if available)
    command = f"echo 'SecurityTrails using: {securitytrails_key}'"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_urlscan(domain, temp_file):
    name = 'urlscan'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    urlscan_api_key = random.choice(api_keys.URLSCAN_API_KEYS)
    # Placeholder command (replace with actual API call if available)
    command = "echo 'urlscan_result_here.com'"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
            f.write(f"URLSCAN_API_KEY={urlscan_api_key}\n".encode())
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_puredns(domain, temp_file):
    name = 'puredns'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    # Placeholder command (replace with actual if available)
    command = "echo 'puredns-result-example.com'"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_censys(domain, temp_file):
    name = 'censys'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    censys_token = random.choice(api_keys.CENSYS_TOKENS)
    command = f"curl -s -H 'Authorization: Bearer {censys_token}' 'https://search.censys.io/api/v3/hosts/{domain}' | jq -r '.result.services[].domain' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")
        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

# waybackurl
def run_waybackurls(domain, temp_file):
    name = 'waybackurls'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()

    command = f"echo {domain} | waybackurls 2>/dev/null"

    try:
        output = subprocess.check_output(command, shell=True, timeout=60)

        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")

        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))
    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))
    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))


def run_knockpy(domain, temp_file):
    name = 'knockpy'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()

    knockpy_path = "/home/boot/.local/bin/knockpy"

    command = f"{knockpy_path} {domain} 2>/dev/null | grep '{domain}' | sort -u"

    try:
        output = subprocess.check_output(command, shell=True, timeout=180)

        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b"\n")

        end_time = time.time()
        print(green(f"[✓] {name} completed (Time: {int(end_time - start_time)}s)"))

    except subprocess.TimeoutExpired:
        print(red(f"[✗] {name} timed out"))

    except subprocess.CalledProcessError:
        print(red(f"[✗] {name} failed (Execution error)"))

def run_amass(domain, temp_file):
    name = 'amass'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"amass enum -d '{domain}' -passive -nocolor 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=200)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b'\n')
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_crobat(domain, temp_file):
    name = 'crobat'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"crobat -s '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=60)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output + b'\n')
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_sudomy(domain, temp_file):
    name = 'sudomy'
    print(yellow(f"[X] Running {name}..."))
    start_time = time.time()
    command = f"sudomy -d '{domain}' -o sudomy_out 2>/dev/null && cat sudomy_out/Subdomains/* 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=240)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_certcrunchy(domain, temp_file):
    name = 'certcrunchy'
    print(yellow(f"[X] Running {name}..."))
    command = f"certcrunchy -d '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=90)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_analyticsrelationships(domain, temp_file):
    name = 'analyticsrelationships'
    print(yellow(f"[X] Running {name}..."))
    command = f"analyticsrelationships -d '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=90)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_lilly(domain, temp_file):
    name = 'lilly'
    print(yellow(f"[X] Running {name}..."))
    command = f"lilly -d '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=70)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_gotator(domain, temp_file):
    name = 'gotator'
    print(yellow(f"[X] Running {name}..."))

    command = (
        f"gotator -sub {domain} -perm {WORDLIST} -depth 2 -numbers 5 "
        f"2>/dev/null | sort -u"
    )
    try:
        output = subprocess.check_output(command, shell=True, timeout=120)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))
def run_galer(domain, temp_file):
    name = 'galer'
    print(yellow(f"[X] Running {name}..."))
    command = f"galer -d '{domain}' 2>/dev/null"
    try:
        output = subprocess.check_output(command, shell=True, timeout=80)
        with open(temp_file, 'ab') as f:
            f.write(f"# Tool: {name}\n".encode())
            f.write(output)
        print(green(f"[✓] {name} completed"))
    except:
        print(red(f"[✗] {name} failed"))

######################################3

# List of tool functions (add/remove here to modify tools easily)
tool_funcs = [
    run_dnsx,
    run_cero,
    run_altdns,
    run_massdns,
    run_findomain2,
    run_dnsbuster,
    run_fofa,
    run_subfinder,
    run_assetfinder,
    run_shuffledns,
    run_findomain,
    run_gau,
    run_crtsh,
    run_github_subdomains,
    run_chaos,
    run_sublist3r,
    run_shodan,
    run_gitlab_subdomains,
    run_securitytrails,
    run_urlscan,
    run_puredns,
    run_censys,
    run_waybackurls,
    run_knockpy,
     run_amass,
    run_crobat,
    run_sudomy,
    run_certcrunchy,
    run_analyticsrelationships,
    run_lilly,
    run_gotator,
    run_galer
]

# Process each domain
total_domains = 0
for domain in domains:
    total_domains += 1
    print(magenta("════════════════════════════════════════════════════════════"))
    print(magenta(f"║ PROCESSING DOMAIN #{total_domains}: {domain}"))
    print(magenta("════════════════════════════════════════════════════════════"))
    print("")
    for func in tool_funcs:
        func(domain, temp_file)
        print("")

# Process all collected subdomains
print(cyan("[*] Processing all collected data..."))
print(yellow("[*] Removing duplicates..."))
subdomains = set()
with open(temp_file, 'r') as f:
    for line in f:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            subdomains.add(stripped)

unique_count = len(subdomains)
with open('all_subdomains.tmp', 'w') as f:
    for sub in sorted(subdomains):
        f.write(sub + '\n')

print(green(f"[✓] Total unique subdomains: {unique_count}"))
print("")

print(yellow("[*] Checking live hosts with httpx..."))
print(blue("[*] This may take a while depending on the number of subdomains..."))
start_time = time.time()
try:
    command = "httpx -l all_subdomains.tmp -silent -follow-redirects 2>/dev/null | awk '{print $1}' | sort -u"
    output = subprocess.check_output(command, shell=True)
    with open('all.txt', 'wb') as f:
        f.write(output)
    end_time = time.time()
    print(green(f"[✓] Live host check completed (Time: {int(end_time - start_time)}s)"))
except subprocess.CalledProcessError:
    print(red("[✗] httpx failed"))
total_alive = len(output.decode().strip().split('\n')) if 'output' in locals() else 0
print("")

# Clean up
os.remove(temp_file)
os.remove('all_subdomains.tmp')

# Final summary
print(magenta("════════════════════════════════════════════════════════════"))
print(magenta("║ FINAL SUMMARY - ALL DOMAINS "))
print(magenta("════════════════════════════════════════════════════════════"))
print(green(f"[*] Total domains processed : {total_domains}"))
print(green(f"[*] Total unique subdomains : {unique_count}"))
print(green(f"[*] Total LIVE subdomains : {total_alive}"))
print(cyan(f"[*] End time : {time.strftime('%Y-%m-%d %H:%M:%S')}"))
print(magenta("════════════════════════════════════════════════════════════"))
print("")
print(yellow(f"[*] All live subdomains saved to: {green('all.txt')}"))
print(green("[✓] Enumeration completed successfully!"))