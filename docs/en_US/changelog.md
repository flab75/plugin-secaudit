# Changelog

## 0.28 (2026-10-24)
False positives reported on the forum:
- `maj_jeedom`: the finding names the pending updates ("Jeedom" for the core); a plugin update read as "Jeedom not up to date".
- `mqtt_anonyme`: the broker is asked (MQTT login without credentials on its ports open to the network) instead of searching files for `allow_anonymous true`, which was wrong on a file not loaded or a local-only listener. The refused "secaudit" client therefore shows in the broker log at each audit. Probed ports: mosquitto process, port 1883, mosquitto / emqx Docker container or one with internal port 1883; without sudo, port 1883 only; 8883 / 8884 (TLS) not probed.

## 0.27 (2026-10-23)
Following Jeedom 4.6.2:
- `jeedom_4_6_2`: Jeedom older than 4.6.2 is reported (PHP protections against a known vulnerability, PHP protections added to Apache's security configuration).
- `apache_security`: reports lines of the security configuration shipped by Jeedom (`install/apache_security`) missing from the active `security.conf`, or `security.conf` disabled or its link broken (Apache only; before 4.5, or without `jeedom.com` in `security.conf`, or a conf-enabled `security.conf` that is not a link, the finding says Jeedom does not copy this file).
- The "Wizard" and "Add my current address" buttons move from `onclick` to the plugin's JavaScript file (ready for a stricter content security policy).
- Adversarial review: lines counted with their repeats (the `php_admin_*` lines are in two blocks), active configuration read, unreadable = error, nothing without Apache.

## 0.26 (2026-10-15)
Diagnostics refined from real cases (Homebridge refused by the API, Signal container open to the network, Debian 12 MariaDB):
- `ssh_password`: the finding says how many SSH keys are installed and who still logs in with a password (30 days); the fix warns not to turn passwords off without a key.
- `mysql_ecoute`: detects the port opened by `mariadb.socket` (systemd, Debian 12), where `bind-address` is ignored; the fix says to disable the socket.
- `zwavejs_ui`: reported only if the API answers without authentication or nothing allows checking it (an open but protected 8091 is no longer a problem).
- `ports_ouverts`: names the Docker container and its Docker management equipment, says whether the port answers without a password; the fix explains `127.0.0.1:PORT` in Docker management (and that a plugin may rewrite it). The wizard lists the ports without probing them.
- `api_refus`: names the refused client (plugin, address), the number of refusals and who owns the key (disabled account…), never the key; a fixed client leaves the finding at once. Fix: restart the plugin daemon when its key belongs to a disabled account.
- `ss` without sudo: ports are still seen, but without process names: a name in "Accepted ports" (homebridge) no longer filters anything, the finding says so.
- Adversarial review: `api_refus` counts per address (a plugin name changed at each try no longer gets under the threshold) and reports 10 refusals from the Internet in 24 h; one refusal per request; refusal lines without a strict timestamp ignored. `ports_ouverts` now probes only Docker and known web servers (not a serial bridge or a daemon socket), "web page served" instead of "without a password" on `/`, Docker port ranges read. `ssh_password` also tests `KbdInteractiveAuthentication`, reads the `sshd` journal and dates its oldest line; fix in `sshd_config.d`. `mysql_ecoute`: simpler fix (disable `mariadb.socket`), "unknown process" without sudo.
- Adversarial review (round 2): `api_refus` keeps the refusals of a request spread over several lines (separate entry, 20 refusals in 24 h reported even without an address), no longer resets the counter on another error, leaves 100.64.0.0/10 (Tailscale) out of Internet refusals, reports "forgeable addresses" when `entetes_ip` fails. `ports_ouverts`: each port of a Docker range, container probed only if its image is known or its internal port is a web port, HTTP code shown when neither 2xx nor 401/403, `docker ps` capped at 10 s. `ssh_password`: keys counted per account, `sshd-session` journal (OpenSSH 9.8+), `journalctl` capped at 10 s.
- Adversarial review (round 3): refusals with no readable request counted only over 24 h (no more lasting false positive), address attribution sturdier against forged lines, "forgeable addresses" also for `remoteip`, `zwavejs_ui` says "authentication disabled", `ssh_password` reports a journal cut by the timeout and reads keys without a final newline.

## 0.25 (2026-10-15)
- `fichiers_publics` fix removed: the plugin no longer moves files outside its own folder (Jeedom market rule). The item is still reported, the resolution says what to do by hand.
- Docs: "Data and privacy" section (what leaves the machine, what is kept and for how long).

## 0.24 (2026-10-15)
- `remoteip` rule: reported only when Apache's remoteip module is enabled (a `remoteip.conf` left by an update with the module disabled gave a false positive).

## 0.23 (2026-10-14)
- Generated texts are now translatable: the report (rule titles, findings, how-to-fix, severities), the intrusion attempt summary and alert, whois profiles, "what it was looking for", the widget and error messages. They follow Jeedom's language (`core/i18n/en_US.json`); the French output is unchanged ("Aucun problème grave" included).
- `tests/selftest.php en_US`: dry run with English texts (plus a translation check).

## 0.22 (2026-10-14)
- English version: interface (`core/i18n/en_US.json`), documentation `docs/en_US/` (user guide, methods, changelog). The **Documentation** window follows Jeedom's language (French otherwise). The report, rules and alerts are still in French.

## 0.21 (2026-10-14)
- `whois` dependency declared (`plugin_info/packages.json`): Jeedom installs it and shows its status.
- Documentation and changelog links (master and beta branches) in `info.json`.
- GitHub repository `flab75/plugin-secaudit` with the Jeedom workflows (PHP 7.4 / 8.0 / 8.2 lint).

## 0.20 (2026-10-14)
- Full "methods and reasons" documentation (`docs/fr_FR/methodes.md`): how each part works and why. "Documentation" button on the plugin page.

## 0.19 (2026-10-14)
- Setup wizard on the plugin page (first visit after installation or this update, then "Wizard" button): widget, whitelist, accepted ports, router checked, first audit. Documented ("Setup wizard").

## 0.18 (2026-10-14) — fixes from the twelfth adversarial review
- Selftest: the temporary blacklist is only set if the real one is empty, and restored without re-checking; a failure no longer leaves it in place.

## 0.17 (2026-10-14) — fixes from the eleventh adversarial review
- Lists: only added entries are checked (an old conflicting entry no longer blocks additions).
- Selftest: temporary blacklist to test the refusal of a covered whitelist entry.
- whiteips_large: trailing line break reported (mask + line break = PHP error in netMatch).

## 0.16 (2026-10-14) — fixes from the tenth adversarial review
- whiteips_large: tab read as netMatch reads it (reported), exact address compared after trim.
- Whitelist: new entry covered by the blacklist refused; unchanged list not re-checked.
- "View the audit" button on the dashboard only (not on designs).

## 0.15 (2026-10-14) — fixes from the ninth adversarial review
- whiteips_large: range bounds, IP and mask validated (an unreadable bound makes netMatch cover almost all of IPv4).
- White IP API fix: unreadable entries skipped (PHP error).
- Run also refused to a non-admin via the API (user key).
- Blacklist refused if it covers your current address or your whitelist.
- Clear the alert possible when fail2ban does not respond; its bans forgotten after 7 days.
- Appeared script excused by a core update only in the core folders.
- Warning of the whiteips fix: IPv6 and unreadable entries.
- Widget: equipment deleted by hand recreated when the configuration is saved.

## 0.14 (2026-10-14)
- Widget: "View the audit" button to the plugin page.

## 0.13 (2026-10-14) — fixes from the eighth adversarial review
- Blacklist without width limit; ignored whitelist entries shown on the page.
- `whiteips_large` becomes a built-in test that reads entries like `netMatch` (spaces, `/08`, `/-1`); in IPv6 only exact addresses pass (star, range, network). `api_whiteip` skips IPv6 entries.
- `chemins_vises`: core excused by an update done after the request (mtime of `core/config/version`); plugins by content older than the request.
- Widget: `lancer` refused to a non-admin account; the object is only reapplied if it changes; a deleted object hides the widget instead of blocking the configuration.
- Unban: fail2ban's answer is read on the last line, a failure is logged; fail2ban silent: its bans are not purged.

## 0.12 (2026-10-14) — fixes from the seventh adversarial review
- `chemins_vises`: an appeared script is only excused if its content is older than the robot's request (mtime); ctime, reset by Jeedom's permission repair, is no longer used.
- Lists: network at most /24 (IPv4) or /48 (IPv6); a wider entry entered before is ignored.
- Summary: a whitelist IP that looked for something other than Jeedom is counted with the outside addresses.
- Whitelist too wide: only `127.0.0.1`, `127.0.0.0/8` and `127.*.*.*` are exempted (`127.0.0.1/0` reported); IPv6 networks wider than a /48 reported.
- "Clear the alert" button for a ban already lifted; a failed fail2ban Unban is reported; an active ban keeps its first-seen time beyond 30 h.

## 0.11 (2026-10-14)
- **Configuration** button on the plugin page.
- `graves` command (critical and high issues) and widget: display object chosen in the configuration.

## 0.10 (2026-10-14) — fixes from the sixth adversarial review
- Lists: network at most /16 (IPv4) or /32 (IPv6). Alert: "warning, also looked for …" if the IP did not request only Jeedom.
- Silent whois really dated (no longer cut off by the full cache nor queried again every hour); no whois for the lists nor for sshd bans alone without attempts.
- Business / cloud offers of ISPs (Orange Business…) classified as hosting provider, no longer home user.
- `chemins_vises`: an appeared script is only excused if it arrived with the plugin or core update (within 10 min); forgotten after 90 days.
- Whitelist too wide: `127.0.0.0/8` accepted; `a-b` ranges outside a /24 and wide `/255.x` masks reported.
- Seen bans dated from when first seen (no more alert two days later); Unban recomputes the alert; a learning or whois error no longer prevents the hourly recomputation.

## 0.9 (2026-10-14) — whitelist and blacklist, fixes from the fifth adversarial review
- Configuration: **whitelist** (your addresses away from home: banned → always an alert) and **blacklist** (never taken for you). IP or CIDR, IPv4/IPv6, checked when saving. They neither ban nor unban anything.
- "Probably you" only for a French home-user connection (or the whitelist): never again for an unrecognized owner or a silent whois. An sshd / recidive ban alone no longer triggers the alert.
- `/plugins/<x>/…` is only a Jeedom call if plugin x is installed.
- Dated alert ("seen banned on …"): a ban at 7:10 read again the next day at 8:00 is recognized.
- `chemins_vises`: a PHP script missing when a robot requested it and present now is reported (backdoor?), without ever executing it.
- Whitelist too wide: `192.*.1.*` and any star before the last byte. `api_whiteip` accepts `127.0.0.0/8` (read with Jeedom's `netMatch`).
- Note: for Jeedom, a star is worth a /24 whatever its position (`10.*` does not cover 10.1.2.3): write networks in CIDR.
- Remote database: can no longer rewrite the text of a local rule (only make it more severe); a new rule must have a title, a key, a known operator (or a max version).

## 0.8 (2026-10-14) — fixes from the fourth adversarial review
- "Probably you" never for a hosting provider, a scanner, a VPN or an IP not yet identified (nor for a Jeedom ban from a French hosting provider).
- "Jeedom calls" family limited to the real entry points (`core/ajax|php|api`, `desktop/php|modal`, same for plugins, `/mobile/`, static files).
- Seen bans kept 30 h (the 8:00 report can read the 7:00 alert). Unban clears them, as well as the IP's Jeedom failure counter.
- `cron5` only re-reads Jeedom bans (no more sudo fail2ban every 5 min); 6 whois per hour at most.
- `entetes_ip` rule: the 4 headers, and mod_remoteip must be disabled.
- Whitelist too wide: any entry wider than a /24; the fix uses the same regex.
- Learned paths truncated to 200 characters; `chemins_vises` also skips .phtml, .phar, .phps.
- `sauvegardes.json` under lock, old value also in the log.
- README reduced to a pointer to the doc; doc corrected.

## 0.7 (2026-10-14) — fixes from the third adversarial review
- Jeedom bans (10 min) are recorded every 5 min (`cron5`, key `bans_vus`, 24 h): the morning alert also sees a ban already lifted.
- Whois of IPs banned by Jeedom first (their country decides the alert).
- A hosted robot or a scanner that only requests Jeedom scripts is no longer taken for you (alert and summary).
- Jeedom static files (`/core/img/…`, `/favicon.ico`…) classified as "Jeedom calls".
- Non-UTF-8 text (whois, paths) cleaned: the history and the whois cache can no longer fail when saving.
- HTML stripped from the texts of the remote database and of the CVEs.
- "White IP API" fix: only touches the API of the clicked rule, refuses if 127.0.0.1 is missing from the whitelist.
- Warning before reducing the whitelist (Docker, VPN).
- New `entetes_ip` rule: Apache must remove X-Forwarded-For & co., which Jeedom trusts for the client IP.

## 0.6 (2026-10-14) — fixes from the second adversarial review
- The "banned IP that is probably you" alert is recomputed every hour (key `tentatives`), no longer only by the midnight audit: the morning report is up to date.
- Alert also for an IP banned by Jeedom (failed passwords) without any suspicious attempt, from France or from a home-user connection.
- Families counted over all attempts of an IP (no longer only the 20 paths kept as examples); `/mobile/` and the Jeedom folders = Jeedom calls.
- History in `data/historique.json` under lock (the page and the crons wrote it at the same time: attempts lost or counted twice).
- A log line can no longer be forged through the referer of a request.
- `Require all denied` refusals (AH01630) and `AH00128` read.
- A remote database can no longer lower the severity of a local rule; `checks_url` https only.
- Silent whois: retried the next day instead of blocking the queue every hour.
- Expired Jeedom bans ignored; IPs banned without attempts no longer counted as "having probed".
- API fix: the confirmation warns that external apps will be refused.
- PHP 8 errors caught (ajax, page).

## 0.5 (2026-10-14) — fixes from the adversarial review
- An attack targeting Jeedom (`/core/.env`, `/plugins/…/database.db`) is no longer classified as "legitimate Jeedom call": this family now only covers missing `.php` scripts, tested last.
- History per IP over 30 days (`secaudit_historique`): since Jeedom cuts the `http.error` log down to ~500 lines, the analysis only covered one day.
- IPs that only requested missing Jeedom scripts (you while travelling, an app) are no longer counted as attackers; if one is banned → alert (page and morning report).
- The whois is done by the hourly cron (20 IPs at most), no longer while the page is displayed; a silent whois is no longer cached for 30 days; no more reverse DNS (chosen by the attacker).
- Default profile "unrecognized owner" (instead of "robot"); Free/Proxad recognized as home-user connections.
- List of never-banned IPs read correctly (it contained bits of words).
- Summary: "The attempts visible in the log were refused…" instead of "All these attempts failed".
- Remote database: `https://` links only, non-text fields ignored (they crashed the rule list).
- Whitelist fix: only removes the entries that are too wide instead of overwriting the list; public files fix: reports the files not moved.
- Selftest: the safeguard uses a temporary file instead of rewriting `data/checks_remote.json`.

## 0.4 (2026-10-14)
- Code split into single-task modules (`core/class/secaudit_*.class.php`): rules, tests, database, fixes, bans, log, whois, attempts, summary, learning.
- Fix: the "Attempts" section crashed (PHP 8.1, `array_merge` on an array indexed by IP).

## 0.3 (2026-10-14)
- Attempt analysis: each IP that probes Jeedom (http.error) is identified (whois, profile: scanner, hosting provider, VPN, home user), its goal guessed (theft of secrets, backdoor…), with a summary in French.
- Learning: the targeted paths are kept every hour; new `chemins_vises` rule (28 rules) that checks that none of them is served here.
- Morning report: "Attempts" line.

## 0.2 (2026-10-14)
- "Bans" section: IPs banned by fail2ban (all jails) and by Jeedom, cause read in http.error, fail2ban log, Unban button.

## 0.1 (2026-10-13)
- First version: 27 rules, NVD update, 3 fixes, dry run.
