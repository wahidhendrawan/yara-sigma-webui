# Yara to Sigma Web UI Converter

This repository contains a simple web‑based application that converts **YARA** rules into
approximate **Sigma** detection rules and generates basic search queries for
Elastic (ELK) and Splunk.  The tool is intended as a starting point for
analysts who wish to reuse existing YARA signatures within a SIEM context.

## Background

YARA rules are used to identify files or processes by matching on text,
hexadecimal patterns and boolean conditions.  A typical YARA rule contains
three sections—`meta`, `strings` and `condition`.  The `meta` section holds
arbitrary key‑value pairs such as the author, date and description of the rule
while the `strings` section defines the byte or text patterns to look for.
The `condition` section defines the boolean logic that must be satisfied for
a match【127208082006522†L82-L100】.

Sigma is a YAML‑based, vendor‑agnostic format for describing log‑based
detections.  A Sigma rule includes fields like `title`, `id`, `status`,
`description`, `logsource` and `detection`【203982238247205†L210-L232】.  Rules can be
converted into SIEM‑specific queries using back‑end libraries or simple
heuristics.

This project does **not** attempt to perform a perfect semantic conversion
between YARA and Sigma.  Instead, it demonstrates one possible mapping:

1.  **Meta** information such as the author, description and date are copied
    into the appropriate Sigma fields when available.  A UUID is generated
    automatically for the Sigma rule identifier.
2.  **Strings** that are defined as plain text patterns are extracted and
    mapped into a detection section.  Each string becomes its own detection
    clause using the `CommandLine|contains` modifier—a common field used in
    many Sigma rules.  Hexadecimal and regular expression patterns are
    currently ignored.
3.  **Condition** logic is translated into either an “all patterns must
    match” or “any pattern may match” rule.  If the original condition
    contains `all of`, the generated Sigma rule will require all patterns to
    be present.  If it contains `any of` or if no keyword is detected,
    matching on any of the patterns will satisfy the rule.
4.  **Queries** for Splunk and Elastic are generated using simple string
    containment expressions.  Splunk queries consist of quoted pattern
    searches joined by either `AND` or `OR`, while Elastic queries use
    Lucene syntax (`message:*pattern*`).  These queries are provided as
    examples and may need further tuning for production environments.

Although the conversion implemented here is simplistic, it offers a useful
demonstration of how YARA signatures can be repurposed to create log
detections.  Feel free to extend the conversion logic, add support for
additional modifiers or integrate with the official [pySigma](https://github.com/SigmaHQ/pySigma)
framework when the appropriate back‑ends are available.

## Usage

1.  Install the Python dependencies (Flask and PyYAML):

    ```bash
    pip install Flask PyYAML
    ```

2.  Launch the web application:

    ```bash
    python app.py
    ```

3.  Navigate to `http://localhost:5000` in a browser.  Paste a YARA rule
    into the input field, choose the desired backend (Elastic or Splunk) and
    click **Convert**.  The page will display the generated Sigma rule as
    well as the corresponding Splunk or Elastic search query.

4.  You can save the Sigma rule or query output for later use.  Note that
    more complex YARA rules may not translate perfectly; manual tuning
    remains important for high‑fidelity detections.

## Limitations

* Only plain text patterns defined in the `strings` section are considered.
  Hexadecimal patterns and regular expressions are ignored.
* The conversion from YARA condition logic to Sigma is simplistic and
  currently supports “any of” vs “all of” semantics only.
* The generated Splunk and Elastic queries serve as illustrative examples
  rather than production‑ready search expressions.  In practice, you may
  want to map the patterns to more specific log fields (e.g. `Image`,
  `CommandLine`, `event.original`, etc.) depending on your environment.

## License

This project is released under the MIT License.  See `LICENSE` for details.
