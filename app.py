import re
import uuid
import datetime
import json
from typing import Dict, List, Any

import yaml
from flask import Flask, render_template, request, make_response


app = Flask(__name__)

BACKENDS: Dict[str, str] = {
    "Elastic Stack": "message",
    "Splunk": "_raw",
    "Carbon Black EDR": "process_cmdline",
    "Microsoft Defender EDR": "ProcessCommandLine",
    "SentinelOne": "sourceprocesscommandline",
    "IBM QRadar": "payload",
    "LogRhythm": "logMessage",
}


def parse_yara_rule(text: str) -> Dict[str, Any]:
    """Parse a YARA rule and extract name, meta fields, strings and basic condition.

    This function only supports simple YARA syntax.  It ignores comments and
    complex constructs.  Only plain‑text strings defined in the `strings` section
    are extracted; hexadecimal and regular expression patterns are skipped.  The
    condition keyword is reduced to either `all` or `any` depending on the
    presence of those keywords in the condition section.  If none are found,
    `any` is used by default.

    Args:
        text: The raw YARA rule text.

    Returns:
        A dictionary with the rule name, meta information, list of extracted
        string patterns and a simplified condition type.
    """
    # Remove C‑style and C++ style comments.
    def remove_comments(s: str) -> str:
        # Remove block comments
        s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
        # Remove line comments
        s = re.sub(r'//.*', '', s)
        return s

    text_no_comments = remove_comments(text)

    # Extract the rule name
    name_match = re.search(r'(?m)^\s*rule\s+([^{\s]+)', text_no_comments)
    name = name_match.group(1) if name_match else 'ConvertedRule'

    # Extract meta section
    meta: Dict[str, str] = {}
    meta_section = re.search(
        r'meta\s*:\s*(.*?)\s*(strings|condition)\s*:',
        text_no_comments,
        flags=re.S | re.I,
    )
    if meta_section:
        meta_body = meta_section.group(1)
        for line in meta_body.splitlines():
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                # Trim whitespace and surrounding quotes
                val = val.strip().strip('"\'')
                meta[key] = val

    # Extract strings section
    strings: List[str] = []
    strings_section = re.search(
        r'strings\s*:\s*(.*?)\s*condition\s*:',
        text_no_comments,
        flags=re.S | re.I,
    )
    if strings_section:
        str_body = strings_section.group(1)
        for line in str_body.splitlines():
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            if '=' in line:
                _key, val = line.split('=', 1)
                val = val.strip()
                # Consider only quoted plain‑text strings
                str_match = re.search(r'"([^"\\]*(?:\\.[^"\\]*)*)"', val)
                if str_match:
                    pattern = str_match.group(1)
                    strings.append(pattern)

    # Extract condition text
    condition_text = ''
    condition_section = re.search(
        r'condition\s*:\s*(.*?)(?:rule\s+\w+|$)',
        text_no_comments,
        flags=re.S | re.I,
    )
    if condition_section:
        condition_text = condition_section.group(1).strip()

    # Determine whether all patterns must match or any pattern may match
    cond_type = 'any'
    if re.search(r'\ball\s+of\b', condition_text, flags=re.I):
        cond_type = 'all'
    elif re.search(r'\bany\s+of\b', condition_text, flags=re.I):
        cond_type = 'any'

    return {
        'name': name,
        'meta': meta,
        'strings': strings,
        'cond_type': cond_type,
    }


def build_sigma_rule(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Construct a Sigma rule dictionary from parsed YARA components.

    The detection section is built using one selection clause per string pattern.
    A simple condition string combining the selections with either logical AND
    or OR is generated depending on the `cond_type` value.

    Args:
        parsed: Output of `parse_yara_rule`.

    Returns:
        A dictionary representing a Sigma rule ready to be serialized to YAML.
    """
    meta = parsed.get('meta', {})
    patterns = parsed.get('strings', [])
    cond_type = parsed.get('cond_type', 'any')

    detection: Dict[str, Any] = {}
    selection_names: List[str] = []

    # Build a selection for each pattern
    for idx, pattern in enumerate(patterns):
        sel_name = f'sel{idx + 1}'
        detection[sel_name] = {'CommandLine|contains': pattern}
        selection_names.append(sel_name)

    # Build the condition string
    if selection_names:
        if cond_type == 'all':
            # All patterns must match
            cond = ' and '.join(selection_names)
        else:
            # Any pattern may match
            cond = ' or '.join(selection_names)
        detection['condition'] = cond
    else:
        # No patterns extracted – match nothing
        detection['condition'] = 'false'

    # Compose the Sigma rule fields
    rule: Dict[str, Any] = {
        'title': parsed.get('name', 'ConvertedRule'),
        'id': str(uuid.uuid4()),
        'status': 'experimental',
        'description': meta.get('description', f'Converted from YARA rule {parsed.get("name", "")}') or '',
        'author': meta.get('author', 'unknown'),
        'date': meta.get('date', datetime.date.today().strftime('%Y/%m/%d')),
        'references': [],
        'tags': [],
        'logsource': {
            'category': 'process_creation',
            'product': 'windows',
        },
        'detection': detection,
        'falsepositives': ['unknown'],
        'level': 'medium',
    }
    return rule


def build_search_query(patterns: List[str], cond_type: str, field: str) -> str:
    """Construct a simple search query for a given field and list of patterns.

    The query uses wildcard matching (`*pattern*`) around each pattern to allow
    partial matches.  Patterns are combined with logical AND or OR depending on
    the specified condition type.  If no patterns are supplied, an empty
    string is returned.

    Args:
        patterns: A list of plain‑text string patterns extracted from the YARA
            rule.
        cond_type: Either ``"all"`` or ``"any"`` to indicate that all
            patterns must match or that any pattern may match.
        field: The name of the field to search against (e.g., ``"message"``,
            ``"_raw"`` or ``"process_cmdline"``).

    Returns:
        A query string appropriate for the back‑end using Lucene/SPL syntax.
    """
    if not patterns:
        return ''
    joiner = ' AND ' if cond_type == 'all' else ' OR '
    # For Splunk searches on _raw we omit wildcard characters around quotes
    # because Splunk automatically tokenises the event; otherwise we include
    # wildcards around each pattern.
    queries: List[str] = []
    for p in patterns:
        if field == '_raw':
            queries.append(f'{field}="*{p}*"')
        else:
            queries.append(f'{field}:*{p}*')
    return joiner.join(queries)


def generate_all_queries(patterns: List[str], cond_type: str) -> Dict[str, str]:
    """Generate queries for all registered back‑ends.

    Args:
        patterns: List of extracted string patterns.
        cond_type: ``"all"`` or ``"any"``.

    Returns:
        A dictionary mapping back‑end names to their corresponding query.
    """
    return {
        backend: build_search_query(patterns, cond_type, field)
        for backend, field in BACKENDS.items()
    }


@app.route('/', methods=['GET', 'POST'])
def index():
    """Render the home page and handle YARA conversions.

    This view accepts either a pasted YARA rule or an uploaded .yar file.
    It parses the rule, constructs a Sigma detection rule and generates
    queries for all supported back‑ends.  The selected back‑end from the
    dropdown is used to display a single query on the page, while a JSON
    representation of the entire conversion (Sigma rule and queries) is
    produced for download.
    """
    yara_text: str = ''
    sigma_text: str = ''
    queries: Dict[str, str] = {}
    json_text: str = ''
    selected_backend = list(BACKENDS.keys())[0]

    if request.method == 'POST':
        # Obtain YARA from form or uploaded file.  Uploaded files take
        # precedence over pasted text.
        yara_text = request.form.get('yara', '')
        uploaded = request.files.get('file')
        if uploaded and uploaded.filename:
            try:
                yara_bytes = uploaded.read()
                yara_text = yara_bytes.decode('utf-8', errors='ignore')
            except Exception:
                yara_text = ''
        # Determine the chosen back‑end; default to the first entry
        selected_backend = request.form.get('backend', selected_backend)

        # Parse and convert the YARA rule
        parsed = parse_yara_rule(yara_text)
        sigma_rule = build_sigma_rule(parsed)
        sigma_text = yaml.dump(sigma_rule, sort_keys=False, allow_unicode=True)

        # Generate queries for all back‑ends
        queries = generate_all_queries(parsed.get('strings', []), parsed.get('cond_type', 'any'))

        # Note: we no longer build or return JSON data here because the
        # front‑end no longer exposes JSON download functionality.  The
        # Sigma rule is still returned as text for display and can be
        # downloaded separately via the /download_sigma route.

    return render_template(
        'index.html',
        yara_text=yara_text,
        sigma_text=sigma_text,
        queries=queries,
        backend=selected_backend,
        backends=list(BACKENDS.keys()),
    )


# The download_json route has been removed because the front‑end no longer
# offers a JSON download.  If needed in the future, this route could be
# reinstated to return a JSON representation of the parsed YARA rule and
# generated queries.


@app.route('/download_sigma', methods=['POST'])
def download_sigma():
    """Serve the Sigma YAML string as a downloadable file.

    The browser posts the YAML content in a hidden form field; this route
    returns it with appropriate headers so that the client saves it as a
    .yml file.  This allows analysts to download only the Sigma rule
    without the additional per‑backend queries.
    """
    content = request.form.get('sigma_data', '')
    response = make_response(content)
    response.headers['Content-Type'] = 'text/yaml; charset=utf-8'
    response.headers['Content-Disposition'] = 'attachment; filename=converted_sigma.yml'
    return response


if __name__ == '__main__':
    # Run the Flask development server
    app.run(debug=True, host='0.0.0.0', port=5000)
