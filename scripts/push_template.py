push_template.py
usage: push_template.py [-h] --template TEMPLATE --index-pattern INDEX_PATTERN [--url URL] [--user USER]
                        [--password PASSWORD] [--template-name TEMPLATE_NAME] [--cert CERT] [--insecure] [--debug]

Push an OpenSearch index template over HTTPS.

options:
  -h, --help            show this help message and exit
  --template TEMPLATE   Path to the mapping template JSON file.
  --index-pattern INDEX_PATTERN
                        Index pattern for the template.
  --url URL             OpenSearch URL (default: https://localhost:9200).
  --user USER           Username for basic auth (optional).
  --password PASSWORD   Password for basic auth (optional).
  --template-name TEMPLATE_NAME
                        Name of the template (defaults to sanitized index pattern).
  --cert CERT           Path to self-signed certificate (PEM format).
  --insecure            Skip SSL certificate verification (not recommended).
  --debug               Enable debugging to print payload and endpoint details.

===============================================================================

import requests
import json
import argparse
import sys
import re
import urllib3

def load_and_verify_template(template_path):
    """Load and verify the mapping template as valid JSON."""
    try:
        with open(template_path, 'r') as file:
            template = json.load(file)
        print("Template loaded and verified as valid JSON.")
        return template
    except json.JSONDecodeError as e:
        print(f"Invalid JSON format in template: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading template file: {e}")
        sys.exit(1)

def sanitize_template_name(index_pattern):
    """Remove wildcards and special characters from index pattern to generate a valid template name."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '', index_pattern)

def push_template(template_path, index_pattern, template_name, opensearch_url, auth=None, cert=None, insecure=False, debug=False):
    """Push the verified template to OpenSearch over HTTPS, optionally ignoring SSL errors."""
    template = load_and_verify_template(template_path)
    
    payload = {
        "index_patterns": [index_pattern],
        "template": template
    }

    endpoint = f"{opensearch_url}/_index_template/{template_name}"
    
    # Suppress SSL warnings if --insecure is used
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if debug:
            print("[WARNING] SSL verification is disabled. Proceed with caution!")

    # Debugging: Print the payload if --debug is enabled
    if debug:
        print(f"Payload being sent to OpenSearch:\n{json.dumps(payload, indent=2)}")
        print(f"Endpoint: {endpoint}")

    try:
        verify = cert if cert else not insecure
        
        response = requests.put(
            endpoint,
            json=payload,
            auth=auth,
            verify=verify
        )
        response.raise_for_status()
        print(f"Template '{template_name}' pushed successfully: {response.json()}")
    except requests.exceptions.HTTPError as e:
        try:
            error_json = response.json()
            print("Error Response (Formatted):")
            print(json.dumps(error_json, indent=2))
        except json.JSONDecodeError:
            print("Failed to decode error response.")
            print(response.text)
        sys.exit(1)
    except requests.exceptions.SSLError as e:
        print(f"SSL error: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Failed to push template: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Push an OpenSearch index template over HTTPS.")
    parser.add_argument("--template", required=True, help="Path to the mapping template JSON file.")
    parser.add_argument("--index-pattern", required=True, help="Index pattern for the template.")
    parser.add_argument("--url", default="https://localhost:9200", help="OpenSearch URL (default: https://localhost:9200).")
    parser.add_argument("--user", help="Username for basic auth (optional).")
    parser.add_argument("--password", help="Password for basic auth (optional).")
    parser.add_argument("--template-name", help="Name of the template (defaults to sanitized index pattern).")
    parser.add_argument("--cert", help="Path to self-signed certificate (PEM format).")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification (not recommended).")
    parser.add_argument("--debug", action="store_true", help="Enable debugging to print payload and endpoint details.")

    args = parser.parse_args()
    
    auth = (args.user, args.password) if args.user and args.password else None
    
    # Generate template name by sanitizing the index pattern if not supplied
    template_name = args.template_name if args.template_name else sanitize_template_name(args.index_pattern)

    push_template(
        args.template,
        args.index_pattern,
        template_name,
        args.url,
        auth,
        cert=args.cert,
        insecure=args.insecure,
        debug=args.debug
    )
