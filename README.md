# YSC (Yara to Sigma Web UI Converter) – Version 1 (classic)

This document describes the original proof‑of‑concept web application for converting **YARA** rules into approximate **Sigma** detection rules and synthesising simple search queries.  It began as a project for Elastic and Splunk and later added support for several EDR platforms.  Analysts can upload or paste YARA signatures, obtain a corresponding Sigma rule and download the resulting YAML file.  This version retains the minimalist user interface and simple conversion logic that make it easy to experiment with detection engineering.

> **Note about Version 2:** A major rewrite of this project is available in the `version‑2` branch.  That version introduces a modular `yar2sig` library, configurable mapping pipelines and a refreshed web UI.  It also supports additional back‑end formats (including *Kusto*, *QRadar* and *ArcSight*) and implements a fallback query generator when the [`sigma‑cli`](https://github.com/SigmaHQ/sigma) tool is not installed.  If you need those features, please refer to the `version‑2` branch and its documentation.

## Background

YARA rules identify files or processes by matching on text, hexadecimal patterns and boolean conditions.  A typical YARA rule contains three sections—`meta`, `strings` and `condition`.  The `meta` section holds arbitrary key–value pairs such as the author, date and description of the rule while the `strings` section defines the byte or text patterns to look for.  The `condition` section defines the boolean logic that must be satisfied for a match ([YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html#metadata)).

Sigma is a YAML‑based, vendor‑agnostic format for describing log‑based detections.  A Sigma rule includes fields like `title`, `id`, `status`, `description`, `logsource` and `detection` (see the [Sigma documentation](https://sigmahq.io/docs/basics/rules.html#metadata)).  Rules can be converted into SIEM‑specific queries using back‑end libraries or simple heuristics.

This project does **not** attempt to perform a perfect semantic conversion between YARA and Sigma.  Instead, it demonstrates one possible mapping:

1. **Meta** information such as the author, description and date are copied into the appropriate Sigma fields when available.  A UUID is generated automatically for the Sigma rule identifier.
2. **Strings** that are defined as plain text patterns are extracted and mapped into a detection section.  Each string becomes its own detection clause using the `CommandLine|contains` modifier—a common field used in many Sigma rules.  Hexadecimal and regular expression patterns are currently ignored.
3. **Condition** logic is translated into either an “all patterns must match” or “any pattern may match” rule.  If the original condition contains `all of`, the generated Sigma rule will require all patterns to be present.  If it contains `any of` or if no keyword is detected, matching on any of the patterns will satisfy the rule.
4. **Queries** for Splunk and Elastic are generated using simple string containment expressions.  Splunk queries consist of quoted pattern searches joined by either `AND` or `OR`, while Elastic queries use Lucene syntax (`message:*pattern*`).  These queries are provided as examples and may need further tuning for production environments.

Although the conversion implemented here is simplistic, it offers a useful demonstration of how YARA signatures can be repurposed to create log detections.  Feel free to extend the conversion logic, add support for additional modifiers or integrate with the official [pySigma](https://github.com/SigmaHQ/pySigma) framework when the appropriate back‑ends are available.

## Usage

1. Install the Python dependencies (Flask and PyYAML):

   ```bash
   pip install Flask PyYAML
   ```

2. Launch the web application:

   ```bash
   python app.py
   ```

3. Navigate to `http://localhost:5000` in a browser.  Upload a `.yar` file or paste a YARA rule into the input field.  Choose the target back‑end from the drop‑down list (Elastic Stack, Splunk, VMware Carbon Black EDR, Microsoft Defender EDR, SentinelOne, IBM QRadar, LogRhythm, etc.) and click **Convert**.  The page will render the generated Sigma rule and display a query for the selected back‑end.  A button beneath the query allows you to download the Sigma rule as a YAML file.

4. You can copy the Sigma rule, review the query for your chosen back‑end and download the Sigma rule for integration with your tooling.  Because the parser only supports plain text string patterns, complex YARA rules and advanced condition logic will require manual refinement before deployment.

## Limitations

* Only plain text patterns defined in the `strings` section are considered.  Hexadecimal patterns and regular expressions are ignored.
* The conversion from YARA condition logic to Sigma remains simplistic and supports only “any of” vs “all of” semantics.
* Only a limited set of SIEM/EDR platforms are configured.  Adding new back‑ends requires associating a suitable default search field with the platform.  For additional back‑ends such as *Kusto*, *QRadar* or *ArcSight*, please see the Version 2 branch.
* Generated queries are heuristic and may require tuning.  For example, you might prefer to search event data using more specific fields such as `Image`, `EventID`, `FileName`, etc., depending on how your telemetry is indexed.

## Contributing

Contributions are highly encouraged.  Detection engineering is an evolving discipline, and community input helps improve both the parsing logic and the quality of the queries.  Feel free to submit pull requests with bug fixes, additional back‑end mappings or UI enhancements.  The project is released under the MIT License; see `LICENSE` for details.
