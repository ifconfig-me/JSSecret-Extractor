#!/usr/bin/env python
import os
import sys
import re
import glob
import argparse
import jsbeautifier
import webbrowser
import base64
import requests
import urllib3
from lxml import html
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from html import escape
from colorama import init, Fore, Style

def show_banner():
    banner = f"""
 {BOLD_BLUE} ███▄    █  ▄▄▄    ██▒   █▓ ███▄    █ {NC}
 {BOLD_BLUE} ██ ▀█   █ ▒████▄ ▓██░   █▒ ██ ▀█   █ {NC}
 {BOLD_BLUE}▓██  ▀█ ██▒▒██  ▀█▄▓██  █▒░▓██  ▀█ ██▒{NC}
 {BOLD_BLUE}▓██▒  ▐▌██▒░██▄▄▄▄██▒██ █░░▓██▒  ▐▌██▒{NC}
 {BOLD_BLUE}▒██░   ▓██░ ▓█   ▓██▒▒▀█░  ▒██░   ▓██░{NC}
 {BOLD_BLUE}░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▐░  ░ ▒░   ▒ ▒ {NC}
 {BOLD_BLUE}░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░░  ░ ░░   ░ ▒░{NC}
 {BOLD_BLUE}   ░   ░ ░   ░   ▒     ░░     ░   ░ ░ {NC}
 {BOLD_BLUE}         ░       ░  ░   ░           ░ {NC}
 {BOLD_BLUE}                       ░               {NC}
    """
    print(banner)

init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

regex_patterns = {
    'google_api': (r'AIza[0-9A-Za-z-_]{35}', 'background-color: #FFCCCC;', Fore.RED),
    'firebase': (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'background-color: #CCFFCC;', Fore.GREEN),
    'google_captcha': (r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$', 'background-color: #CCCCFF;', Fore.BLUE),
    'google_oauth': (r'ya29\.[0-9A-Za-z\-_]+', 'background-color: #FFFFCC;', Fore.YELLOW),
    'amazon_aws_access_key_id': (r'A[SK]IA[0-9A-Z]{16}', 'background-color: #FFCCFF;', Fore.MAGENTA),
    'amazon_mws_auth_token': (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'background-color: #CCFFFF;', Fore.CYAN),
    'amazon_aws_url': (r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com', 'background-color: #FFCCCC;', Fore.RED),
    'facebook_access_token': (r'EAACEdEose0cBA[0-9A-Za-z]+', 'background-color: #CCFFCC;', Fore.GREEN),
    'authorization_basic': (r'basic [a-zA-Z0-9=:_\+\/-]{5,100}', 'background-color: #CCCCFF;', Fore.BLUE),
    'authorization_bearer': (r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}', 'background-color: #FFFFCC;', Fore.YELLOW),
    'authorization_api': (r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}', 'background-color: #FFCCFF;', Fore.MAGENTA),
    'mailgun_api_key': (r'key-[0-9a-zA-Z]{32}', 'background-color: #CCFFFF;', Fore.CYAN),
    'twilio_api_key': (r'SK[0-9a-fA-F]{32}', 'background-color: #FFCCCC;', Fore.RED),
    'twilio_account_sid': (r'AC[a-zA-Z0-9_\-]{32}', 'background-color: #CCFFCC;', Fore.GREEN),
    'twilio_app_sid': (r'AP[a-zA-Z0-9_\-]{32}', 'background-color: #CCCCFF;', Fore.BLUE),
    'paypal_braintree_access_token': (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', 'background-color: #FFFFCC;', Fore.YELLOW),
    'square_oauth_secret': (r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}', 'background-color: #FFCCFF;', Fore.MAGENTA),
    'square_access_token': (r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}', 'background-color: #CCFFFF;', Fore.CYAN),
    'stripe_standard_api': (r'sk_live_[0-9a-zA-Z]{24}', 'background-color: #FFCCCC;', Fore.RED),
    'stripe_restricted_api': (r'rk_live_[0-9a-zA-Z]{24}', 'background-color: #CCFFCC;', Fore.GREEN),
    'github_access_token': (r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*', 'background-color: #CCCCFF;', Fore.BLUE),
    'rsa_private_key': (r'-----BEGIN RSA PRIVATE KEY-----', 'background-color: #FFFFCC;', Fore.YELLOW),
    'ssh_dsa_private_key': (r'-----BEGIN DSA PRIVATE KEY-----', 'background-color: #FFCCFF;', Fore.MAGENTA),
    'ssh_ec_private_key': (r'-----BEGIN EC PRIVATE KEY-----', 'background-color: #CCFFFF;', Fore.CYAN),
    'pgp_private_block': (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'background-color: #FFCCCC;', Fore.RED),
    'json_web_token': (r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', 'background-color: #CCFFCC;', Fore.GREEN),
    'slack_token': (r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"', 'background-color: #CCCCFF;', Fore.BLUE),
    'ssh_priv_key': (r'([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)', 'background-color: #FFFFCC;', Fore.YELLOW),
    'heroku_api_key': (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 'background-color: #FFCCFF;', Fore.MAGENTA),
    'possible_creds': (r'(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)', 'background-color: #CCFFFF;', Fore.CYAN),
}

html_template = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecretFinder Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .container {{ margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; }}
        .result {{ margin: 10px 0; }}
        .result div {{ padding: 5px; }}
        .highlight {{ {highlight_style} }}
    </style>
</head>
<body>
    <div class="container">
        $$content$$
    </div>
</body>
</html>
'''

def display_error(message):
    print(f'Error: {message}')
    sys.exit(1)

def get_context(matches, content, name, context_window=50):
    items = []
    unique_matches = list(set([match[0] for match in matches]))
    for match in unique_matches:
        context = re.findall(f'.{{0,{context_window}}}{re.escape(match)}.{{0,{context_window}}}', content, re.IGNORECASE)
        items.append({
            'matched': match,
            'name': name,
            'context': context,
            'multi_context': len(context) > 1
        })
    return items

def scan_file(content, mode=1, extra_regex=None):
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for name, (pattern, _, _) in regex_patterns.items():
        regex = re.compile(pattern, re.VERBOSE | re.IGNORECASE)
        matches = [(match.group(), match.start(), match.end()) for match in re.finditer(regex, content)]
        items = get_context(matches, content, name)
        all_items.extend(items)

    if extra_regex:
        extra_regex = re.compile(extra_regex, re.VERBOSE | re.IGNORECASE)
        all_items = [item for item in all_items if extra_regex.search(item['matched'])]

    return all_items

def parse_input(input_path):
    if os.path.isfile(input_path):
        return [input_path]
    if os.path.isdir(input_path):
        return glob.glob(os.path.join(input_path, '**/*.js'), recursive=True)
    display_error('Invalid input path.')

def save_html(output):
    try:
        with open(args.output, "w", encoding='utf-8') as file:
            file.write(html_template.replace('$$content$$', output))
        print(f'Output saved to file://{os.path.abspath(args.output)}')
        webbrowser.open(f'file://{os.path.abspath(args.output)}')
    except Exception as e:
        display_error(f'Error saving output: {e}')

def cli_output(matches):
    for match in matches:
        name = match['name']
        color = regex_patterns[name][2]
        print(f'{color}{name}\t->\t{match["matched"]}{Style.RESET_ALL}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input folder containing JS files", required=True)
    parser.add_argument("-o", "--output", help="Where to save the file, including file name. Default: output.html", default="output.html")
    parser.add_argument("-r", "--regex", help="RegEx for filtering purposes against found endpoints (e.g., ^/api/)")
    args = parser.parse_args()

    js_files = parse_input(args.input)

    final_output = ''
    for js_file in js_files:
        print(f'[ + ] File: {js_file}')
        with open(js_file, 'r', encoding='utf-8') as file:
            content = file.read()
        matches = scan_file(content, mode=1, extra_regex=args.regex)
        if args.output == 'cli':
            cli_output(matches)
        else:
            final_output += f'<h1>File: {escape(js_file)}</h1>'
            for match in matches:
                highlight_style = regex_patterns[match['name']][1]
                highlighted_context = match['context'][0] if match['context'] else match['matched']
                final_output += f'<div class="result"><div><strong>{match["name"]}</strong></div><div class="highlight" style="{highlight_style}">{escape(highlighted_context)}</div></div>'
    
    if args.output != 'cli':
        save_html(final_output)
