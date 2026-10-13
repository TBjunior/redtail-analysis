# RedTail across five vectors: one campaign observed on a T-Pot honeypot (September 2026)

Thaddäus Bischoff · Dual-study student (B.Eng. Information Technology)

A single T-Pot honeypot recorded one continuous RedTail campaign between 2026-09-16 and 2026-09-28 on five vectors: SSH, Telnet, HTTP, HTTPS and the Docker API. This repository contains the full report and the indicators.

## Key findings

- **Five vectors, one operation.** 24 SSH sessions, 19 Telnet sessions, 699 HTTP requests, 741 HTTPS requests and 31 Docker API requests share one SSH key fingerprint, staging servers in one network and identical tooling. I assess this as one operation (high confidence).
- **Telnet.** None of the public reports I reviewed (as of 2026-09-30) documents Telnet as a RedTail infection path.
- **Detection gap.** 40 of the 49 web requests per pass raised no alert with the ET Open ruleset; 37 of them are GET-only probes for PHPUnit files.
- **Defenses are basic.** No password logins over SSH, no Telnet, no exposed Docker API, no development tools in the web root, plus alerts on bursts of 404 responses and on changes to `authorized_keys`.
- **Limits.** One sensor, one time window. All numbers are lower bounds, because a 21-hour outage on 2026-09-22 left a gap in the data.

## Contents

| Path | What it is |
|---|---|
| [`report/`](report/) | Full report (English) |
| [`iocs/iocs.csv`](iocs/iocs.csv) | Indicators from Section 8 of the report, one per row |
| [`CITATION.cff`](CITATION.cff) | Citation metadata |
| [`LICENSE`](LICENSE) | CC BY 4.0 |

## Using the indicators

- The CSV contains raw values (not defanged), so tools can read them. The report uses defanged forms. Do not open the URL in a browser.
- IP addresses age quickly.
- Some indicators (SSH banner, HASSH, User-Agent) match legitimate software or can be forged. Use them only in combination with other indicators, as described in Section 8 of the report.
- All indicators were observed between 2026-09-16 and 2026-09-28 (UTC).
- `first_seen` and `last_seen` are UTC and taken from the report (Sections 5.1, 5.3 and 5.4). `dates_basis` states which statement each pair rests on. Where the report gives no times for an individual indicator, the values are the outer bounds of the vectors on which it appears, and `dates_basis` says so. Date-only values mean the report gives no time.
- This repository contains no malware samples, only hashes.

## Status

Snapshot of observations from 2026-09-16 to 2026-09-28. Not maintained. Last updated: 2026-10-13.

## License

Copyright (c) 2026 Thaddäus Bischoff. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See [`LICENSE`](LICENSE).

Please credit: Thaddäus Bischoff, "RedTail Across Five Vectors: One Campaign Observed on a T-Pot Honeypot, September 2026", https://github.com/TBjunior/redtail-analysis (CC BY 4.0).

## Disclaimer

This is a personal research project. It is not affiliated with or endorsed by my university or employer.

## Kurzfassung (Deutsch)

Ein einzelner T-Pot-Honeypot hat vom 16. bis 28. September 2026 (UTC) eine zusammenhängende RedTail-Kampagne über fünf Wege aufgezeichnet: 24 SSH-Sitzungen, 19 Telnet-Sitzungen, 699 HTTP-Anfragen, 741 HTTPS-Anfragen und 31 Anfragen an die Docker-API. Derselbe SSH-Schlüssel-Fingerabdruck, Staging-Server in einem einzigen Netz und identische Werkzeuge treten auf allen Angriffswegen auf. Ich bewerte das als eine einzige Operation (hohe Sicherheit). Telnet als Infektionsweg ist in den von mir gesichteten öffentlichen Berichten nicht dokumentiert. Von den 49 Web-Anfragen eines Durchlaufs lösten 40 mit dem Regelsatz ET Open keinen Alarm aus. Die Kampagne lief nach dem Analysefenster weiter. Verteidiger erreichen am meisten mit Grundlagen: keine Passwort-Anmeldung per SSH, kein Telnet, keine offene Docker-API, keine Entwicklungswerkzeuge im Web-Root, dazu Alarme bei gehäuften 404-Antworten und bei Änderungen an `authorized_keys`. Alle Zahlen beschreiben einen Sensor und sind Untergrenzen, denn am 22. September fehlen rund 21 Stunden Daten.
