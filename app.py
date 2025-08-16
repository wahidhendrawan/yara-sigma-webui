from flask import Flask, render_template, request
import uuid
import datetime
import yaml

app = Flask(__name__)

def parse_yara_rule(text):
    name = 'ConvertedRule'
    lines = text.splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('rule '):
            parts = stripped.split()
            if len(parts) >= 2:
                name = parts[1]
            break
    meta = {}
    strings = []
    section = None
    dq = chr(34)
    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith('meta:'):
            section = 'meta'
            continue
        if lower.startswith('strings:'):
            section = 'strings'
            continue
        if lower.startswith('condition:'):
            section = 'condition'
            continue
        if section == 'meta' and '=' in stripped:
            key, value = [x.strip() for x in stripped.split('=',1)]
            if len(value) >= 2 and value[0] == dq and value[-1] == dq:
                value = value[1:-1]
            meta[key] = value
        elif section == 'strings' and '=' in stripped:
            _, value = stripped.split('=',1)
            v = value.strip()
            if v.startswith(dq):
                parts2 = v.split(dq)
                if len(parts2) > 2:
                    strings.append(parts2[1])
    cond_type = 'any'
    for line in lines:
        lower = line.lower()
        if 'all of' in lower:
            cond_type = 'all'
            break
        if 'any of' in lower:
            cond_type = 'any'
            break
    return {'name': name, 'meta': meta, 'strings': strings, 'cond_type': cond_type}

def build_sigma_rule(parsed):
    meta = parsed.get('meta', {})
    patterns = parsed.get('strings', [])
    cond_type = parsed.get('cond_type', 'any')
    detection = {}
    names = []
    for i, pattern in enumerate(patterns):
        sel = 'sel' + str(i+1)
        detection[sel] = {'CommandLine|contains': pattern}
        names.append(sel)
    if names:
        if cond_type == 'all':
            detection['condition'] = ' and '.join(names)
        else:
            detection['condition'] = ' or '.join(names)
    else:
        detection['condition'] = 'false'
    desc = meta.get('description')
    if desc:
        description = desc
    else:
        description = 'Converted from YARA rule ' + parsed.get('name','')
    rule = {
        'title': parsed.get('name', 'ConvertedRule'),
        'id': str(uuid.uuid4()),
        'status': 'experimental',
        'description': description,
        'author': meta.get('author','unknown'),
        'date': meta.get('date', datetime.date.today().strftime('%Y/%m/%d')),
        'references': [],
        'tags': [],
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': detection,
        'falsepositives': ['unknown'],
        'level': 'medium'
    }
    return rule

def generate_query(patterns, cond_type, backend):
    if not patterns:
        return ''
    joiner = ' AND ' if cond_type == 'all' else ' OR '
    if backend == 'splunk':
        return joiner.join([p for p in patterns])
    elif backend == 'elastic':
        return joiner.join(['message:*' + p + '*' for p in patterns])
    else:
        return ''

@app.route('/', methods=['GET','POST'])
def index():
    yara_text = ''
    sigma_text = ''
    query_text = ''
    backend = 'elastic'
    if request.method == 'POST':
        yara_text = request.form.get('yara','')
        backend = request.form.get('backend','elastic')
        parsed = parse_yara_rule(yara_text)
        sigma_rule = build_sigma_rule(parsed)
        sigma_text = yaml.dump(sigma_rule, sort_keys=False, allow_unicode=True)
        query_text = generate_query(parsed.get('strings', []), parsed.get('cond_type','any'), backend)
    return render_template('index.html', yara_text=yara_text, sigma_text=sigma_text, query_text=query_text, backend=backend)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
