# Security audit: methods and reasons

This document explains how the plugin works and why it was built this way. The short user guide is in `docs/en_US/index.md`.
Each "Why" answers a real problem met during development, most of the time raised by an adversarial review (see the changelog).

## 1. Principles

- **Report, do not act.** The audit reads the configuration and the system, it changes nothing. The only changes are the two fixes, started by hand by an administrator after confirmation, with a backup of the old value. Why: a security tool that changes the machine on its own can cut off access (API, SSH, whitelist) at a moment when nobody is watching.
- **Nothing leaves the machine**, except three requests: downloading the vulnerability database (NVD), the additional database if you provide one, and `whois` requests on the IPs that probed Jeedom. The report, the history and the lists stay local.
- **Administrators only.** The page, the ajax and the "Run" (« Lancer ») command check the admin profile. Why: the report describes your weaknesses, and on a standard Jeedom installation a Jeedom administrator is root on the machine (see the `sudo_www` rule).
- **Data coming from outside is never code.** Neither the downloaded database, nor the paths requested by bots, nor the whois answers can trigger a command or inject HTML.
- **Known limits are written in the code** (`ponytail:` comments) and repeated in chapter 14, instead of being hidden.

## 2. Code organization

The `secaudit` class (file `core/class/secaudit.class.php`) holds the equipment, the audit launch, the crons and the wizard. Each task is in its own module, loaded automatically:

| Module | Role |
|---|---|
| `secaudit_regles` | reads the rules (local and downloaded), filters the remote database, evaluates a rule |
| `secaudit_tests` | built-in tests (type `builtin`): each returns [problem?, detail] |
| `secaudit_base` | downloads the known vulnerabilities (NVD) and the additional database |
| `secaudit_correctifs` | the two fixes and the backup of the old values |
| `secaudit_journal` | reads `log/http.error` and guesses the goal of each attempt |
| `secaudit_historique` | keeps the attempts per IP over 30 days |
| `secaudit_whois` | owner of an IP and guessed profile |
| `secaudit_bans` | fail2ban and Jeedom bans, memory of seen bans, unbanning |
| `secaudit_tentatives` | combines history, bans and whois for the page and the report |
| `secaudit_resume` | plain-language summary and "probably you" alert |
| `secaudit_listes` | whitelist and blacklist from the configuration |
| `secaudit_apprentissage` | remembers the paths targeted from outside |
| `secaudit_doc` | shows this document in the plugin page |

Why modules: each part can be reread and tested on its own, and an error in one (whois, log) does not stop the others from running.

## 3. What runs, and when

| Cron | What it does | Why this frequency |
|---|---|---|
| every 5 min (`cron5`) | records current Jeedom bans | a Jeedom ban lasts 10 min by default: the hourly cron would almost never see it. fail2ban is not read here (sudo every 5 min would fill `auth.log`); its bans last hours, the hourly cron is enough |
| every hour (`cronHourly`) | path learning, whois (6 IPs at most), recomputation of the summary and the alert | Jeedom trims `http.error` to a few hundred lines: read every hour, nothing is lost. The alert must be fresh for the morning report |
| every night (`cronDaily`) | update of the vulnerability database, then full audit | the audit takes about one minute (shell commands, sudo, local requests): once a day is enough for a configuration that changes little |

Each step of the hourly cron is protected separately: a learning or whois error is written to the `secaudit` log but does not prevent the alert from being recomputed. Otherwise the morning report would read the previous hour's alert without knowing it.

## 4. The audit

### The rules
Each rule has an identifier, a title, a severity, a resolution and a type:

| Type | Method | Example |
|---|---|---|
| `config` | compares a Jeedom configuration key to a value (operators eq, neq, gt, lt, empty, regex) | HTTP API in "enable" mode |
| `core_version` | compares the core version to a maximum version (included or excluded) | known vulnerabilities (CVE) |
| `shell` | runs a command (20 s at most) and looks for a pattern in its output | `sshd -T` for the actual SSH configuration |
| `builtin` | calls a test written in PHP in `secaudit_tests` | two-factor authentication of admins |

A rule that crashes gives the "error" (« erreur ») state with the message, without stopping the others.

### The score
The score starts at 100 and each problem removes points: critical 25, high 10, medium 4, info 0. Why these weights: a single critical item (root access possible from the Internet) must drop the score below 80; four medium problems weigh less than one high problem; "info" items describe without judging (platform, standard sudo, router reminder) and must not penalize a normal installation.

### Messages
A **new** problem of high or critical severity creates a Jeedom message (compared with the previous report). Why only new ones: a message every night for the same item would soon be ignored.

### What each rule checks

| Rule | Severity | Method | Why |
|---|---|---|---|
| `plateforme` | info | `systemd-detect-virt`, Raspberry model, `/.dockerenv`, `/etc/os-release` | read the other items in their context: on a VM, security also depends on the host, which the plugin cannot see |
| `admins_2fa` | high | active admin profiles without two-factor authentication | Jeedom admin = root (passwordless sudo): one stolen password is enough to take over the machine |
| `users_disabled` | info | disabled accounts still present | a forgotten account can be re-enabled; better delete it |
| `api_http`, `api_jsonrpc`, `api_tts` | high / medium | API mode = "enable" (open to any address with the key) | an API key leaks easily (shortcuts, screenshots, apps); in "White IP" (« IP blanche ») mode, a stolen key is useless outside your addresses |
| `whiteips_large` | medium | entries of the Jeedom whitelist wider than a /24, read the way Jeedom reads them (chapter 7) | an address in the whitelist is never banned: `10.*` or a /16 allows unlimited password guessing |
| `ban_seuil` | medium | more than 10 failed logins before a ban | beyond that, banning no longer slows down password guessing |
| `https_externe` | high | external access declared as `http://` | passwords and API key would travel in clear text |
| `certificat` | high | local HTTPS certificate expiring in less than 21 days | certbot renews at 30 days: at 21, automatic renewal has already failed at least once |
| `maj_jeedom` | medium | pending core and plugin updates | fixed vulnerabilities become public after the update |
| `maj_securite_debian` | medium | `apt-get -s upgrade` (simulation, nothing is installed), packages from the security repository | same for the system |
| `fichiers_publics` | medium | .js, .css, .html, .htm, .txt files at the root of `data/` | Apache serves them without login: backups or exports there become readable from the Internet |
| `chemins_vises` | high | chapter 11 | a successful attempt does not appear in the error log: you have to go and look |
| `entetes_ip` | high | no `RequestHeader unset` for X-Forwarded-For, X-Real-IP, CF-Connecting-IP, Client-IP, or mod_remoteip active | Jeedom reads these headers to learn the client IP: an attacker who sends them picks their IP and bypasses banning and whitelist |
| `ssh_root` | high | `sshd -T` (configuration actually applied, included files too): `permitrootlogin yes` | root is the first account tried by bots |
| `ssh_password` | medium | `sshd -T`: `passwordauthentication yes` or `kbdinteractiveauthentication yes` (password through PAM). Finding: installed keys per account (`authorized_keys` of root and /home) and password logins over the last 30 days (`sshd` journal and `sshd-session` for OpenSSH 9.8+: user, addresses), with the date of the oldest journal line (a journal wiped at reboot does not cover 30 days); reading capped at 10 s, reported if cut | with keys only, password guessing leads nowhere. The finding tells whether it is safe to turn passwords off: with no key, or if a user still logs in with a password, access would be lost |
| `ssh_x11` | info | `sshd -T`: `x11forwarding yes` | useless on a server, extra attack surface |
| `fail2ban` | medium | `fail2ban-client ping` | without it, bots try SSH and web pages endlessly |
| `remoteip` | medium | `RemoteIPHeader` without `RemoteIPTrustedProxy` | same consequence as `entetes_ip`: client IP can be forged |
| `mysql_ecoute` | medium | `ss`: port 3306 listening on all interfaces. Finding: port held by systemd (`mariadb.socket`) or by MariaDB (unknown process without sudo) | Jeedom only uses the database locally. On Debian 12, `mariadb.socket` opens the port itself: `bind-address` is then ignored and the fix changes |
| `zwavejs_ui` | medium | `ss`: port 8091 listening on all interfaces **and** its API (`/api/settings`, from 127.0.0.1) answers without authentication, or its authentication is disabled (`gateway.authEnabled` setting of the zwavejs plugin), or there is no way to know | the Z-Wave JS UI interface can exclude or reset the whole Z-Wave network. Open to the network but password-protected is not a problem. The default password is not tried (that would be a login attempt) |
| `ports_ouverts` | medium | `ss -tlnp`: ports listening on all interfaces, except "Accepted ports" (port number or process name). Finding: Docker container (name, image, Docker management equipment, each port of a range) and, only for known web servers (node, nginx…) and containers whose image is known or whose internal port is a common web port (80, 443, 8080…), answer to a password-less HTTP request from 127.0.0.1: "answers without a password" (known API path, e.g. Signal), "web page served" (a login page answers 200 too), "asks for a password", otherwise the HTTP code. Without sudo, process names are invisible: no port probed, only port numbers in "Accepted ports" count | a password-less service open to the local network is at the mercy of any infected device in the house. The process name is for services whose port changes (Homebridge). The HTTP request tells right away whether the port is really open to all (the Signal API sends messages for whoever asks) |
| `api_refus` | medium | last 200 KB of the `api` log: each "Error code 2" (timestamped line) marks the request logged just before as refused; another code marks it as an error (neither refused nor accepted); a refusal with no readable request just before (body over several lines) only counts in the 24 h totals below, with the address of the "- IP :" line if any. Consecutive refusals of each client (plugin + address) since its last accepted request, added up per address: reported at 3 or more (changing the plugin name does not get under the threshold). Also reported: 10 refusals or more from public addresses in 24 h (except 100.64.0.0/10, Tailscale), all clients together; failing that, 20 refusals or more in 24 h, all addresses. "forgeable addresses" added if the `entetes_ip` or `remoteip` rule failed at the last audit. Finding: who owns the key (active account, disabled account, unknown key, valid key), never the key itself | a client refused over and over is either one of your apps misconfigured, or someone trying keys. Real case: a plugin daemon keeps the key of an admin disabled since then (Homebridge); restarting it is enough. A fixed client leaves the finding at once, even if its old refusals stay in the log. The `api` log holds the raw request body: a client can forge lines in it, the finding is a lead, not a proof |
| `mqtt_anonyme` | high | `allow_anonymous true` in mosquitto or the MQTT Manager plugin | any anonymous client can drive the Zigbee and Z-Wave devices |
| `sudo_www` | info | `sudo -l` of www-data: NOPASSWD ALL | Jeedom standard, but explains why 2FA and a restricted API matter so much |
| `box_ports` | info | "Router port forwarding checked" box | the plugin cannot see the router: only a reminder is possible |
| CVE | from the NVD | core version lower than the fixed version | public vulnerability, exploitable by bots |

The `config` and `shell` rules are in `data/checks.json`, readable and editable without touching the PHP.

## 5. The known vulnerability database

Every night, and through the "Update the database" button, the plugin queries the NVD (public NIST database) for the word "jeedom". Each CVE targeting `jeedom:jeedom` with a maximum version becomes a `core_version` rule, with the CVSS severity mapped (CRITICAL to critical, HIGH to high, MEDIUM to medium, LOW to info). The result is written to `data/checks_remote.json`.

An optional additional database (`https://` URL in the configuration) can add its own rules, in the same format as `checks.json`.

**Safeguard.** A downloaded file can be booby-trapped (compromised server, hijacked URL). It is therefore filtered on every read, not only on download:

- it can **never** bring a shell command or a fix: that would be remote code execution on your machine as root;
- on a local rule, it can only **raise** the severity: never lower it (it would silence the audit), never rewrite title or resolution (a booby-trapped resolution would be followed to the letter by the user);
- a new rule is accepted only if complete, of type `config` (key, known operator, value) or `core_version` (maximum version);
- HTML is stripped from texts, and a link that does not start with `https://` is removed (no `javascript:`);
- a field that is not text (array…) makes the rule ignored, otherwise PHP 8 would crash the whole list.

This safeguard is the first item checked by the test (chapter 14).

Limit: only the upper bound of the versions is read. An old vulnerability can therefore be reported wrongly on an older branch that is still maintained.

## 6. The fixes

The "Fix" button exists only for two rules, with a fix written in the plugin. It is read **only from the local database**: the downloaded database cannot add any. A confirmation is always requested, with a warning specific to the rule.

| Fix | What it does | Why these precautions |
|---|---|---|
| `api_whiteip` | switches **the API of the clicked rule** to "White IP" | only that one, because the warning shown only mentioned it. Refused if the Jeedom whitelist does not cover 127.0.0.1: otherwise local plugins (Homebridge…) would lose the API. The check uses `netMatch`, Jeedom's own function |
| `whiteips` | removes from the Jeedom whitelist the entries that are too wide or unreadable, keeps the others, adds 127.0.0.1 and your local subnet | same reading as the `whiteips_large` rule, so that the fix removes exactly what the rule reports |

Before each fix, the old value is written to `data/sauvegardes.json` (file locked during the write) **and** to the `secaudit` log. Why both: the file is in the plugin folder and disappears if the plugin is reinstalled, the log stays. The audit is rerun right after to show the result.

The other items touch the system (SSH, MariaDB, Apache…): a mistake could cut off access to the machine. The resolution describes the steps, to be done by hand.

## 7. Reading the whitelist the way Jeedom reads it

The Jeedom whitelist (`security::whiteips`) is read by its `netMatch` function, which has surprising behaviors. The plugin reproduces them so as not to say "all is well" when Jeedom understands something else:

- an address where a number starts with 0 (`192.168.1.01`) or a badly written range makes the range start at 0.0.0.0: all of IPv4 is covered;
- an unreadable mask, or a line break after the mask, causes a PHP error;
- `127.*` does not cover 127.0.0.1 for `netMatch` (you need `127.*.*.*` or `127.0.0.0/8`);
- spaces are removed but not tabs: a tab in the middle breaks the reading;
- in IPv6, `netMatch` cannot read a network: a star or a range covers all of IPv6, a prefix longer than 32 bits causes a PHP error. Only an exact IPv6 address is safe.

This is the job of the `secaudit_tests::large()` function, used by the rule, by the fix and by the check of the `api_whiteip` fix.

## 8. Intrusion attempts

### Reading the log
The plugin reads the last 20,000 lines of `log/http.error`. It keeps three kinds of lines: Apache refusals ("client denied"), directory not served, missing script or file. For each one: date, IP, path, and whether it was a missing PHP script.

The pattern requires `[client …]` to directly follow the other brackets of the header. Why: an attacker can write text into the line (through the referer). Without this precaution, they could forge a fake attempt in the name of another IP, for example yours.

### What it was looking for
The goal is guessed from the path, first matching pattern wins: theft of secrets (`.env`, `wp-config`, `.git`, backups…), backdoor left by another attacker, diagnostic pages, administration tools, CMS, network devices, and finally "Jeedom request for a missing script".

- "Jeedom" comes last and only for a Jeedom PHP entry point, the mobile app, or an image, stylesheet or script from the Jeedom folders. Why: `/core/.env` or `/plugins/x/data/base.db` are attacks, not Jeedom calls.
- A `/plugins/x/…` path counts as Jeedom only if plugin x is installed here. Otherwise it is a bot looking for a vulnerable plugin.
- Paths that no pattern recognizes are listed separately on the page, to enrich the families.

### 30-day history
Jeedom trims `http.error` to a few hundred lines: without memory, a bot that came the day before would have vanished. Attempts are therefore accumulated per IP in `data/historique.json`: count, first and last time, families (counted over all attempts), 20 example paths of 200 characters at most.

- A marker ("seen", « vu ») remembers the date of the last counted line: reading the log every hour never counts the same attempt twice.
- Locked file: the page and the crons (hourly and daily run together at midnight) write it without stepping on each other.
- Limits: 30 days, 500 IPs, truncated paths. Why: the paths are chosen by the attacker and can be several KB long; without a limit, a bot could grow the file at will.
- If encoding fails (binary text), the old file is kept instead of being emptied.

### Who is behind the IP
`whois` gives the owner and the country; a profile is deduced from them: scanner from a security company, VPN, rented server at a hosting provider, residential connection (machine probably infected), "your home network" (private, reserved or Tailscale 100.64.0.0/10 network), or "unrecognized owner".

- whois takes up to 10 s: it runs **only in the hourly cron**, 6 IPs at most per run (the other plugins wait behind the hourly cron). The page only reads the cache.
- Order: first the IPs banned by Jeedom (their country decides the alert), then the banned or persistent IPs (3 attempts at least). Skipped: the IPs in the lists, and those banned only by sshd or recidive without any web attempt (whois does not change the alert for them and would take the slots).
- Kept 30 days, 300 IPs. A silent whois is retried only the next day, otherwise it would block the queue every hour.
- No reverse DNS: it is slow, and its name is chosen by the owner of the IP. A bot named "shodan" would pass itself off as a harmless scanner.
- Answers are cleaned of their encoding (Latin-1, EUC-KR…) before being stored: otherwise saving would fail and the whole cache would be lost.

### Bans
The plugin reads the bans of **all** fail2ban jails (`fail2ban-client`, through sudo) and those of Jeedom (`security::banip` cache). Jeedom only purges its expired bans at the next login: only bans still active are kept.

**Memory of seen bans (`bans_vus`).** A Jeedom ban lasts 10 minutes: lifted before the hourly cron, it would go unnoticed, whereas it is precisely the one that concerns you (failed passwords from the app). Bans are therefore recorded every 5 minutes, with the date they were **first** seen, and kept 30 hours.

- 30 hours and not 24: the 8 am report runs at the same time as the hourly cron and may read the 7 am alert. A ban seen at 7:10 am must still be there the next day at 8 am.
- Date first seen: a fail2ban ban of 8 hours, seen again every hour, would otherwise stay 38 hours in the window, and the alert would come out two days later without an Unban button.
- A ban still active stays in memory beyond 30 hours (long or permanent bans), otherwise it would be purged and then seen again with a new date.
- If fail2ban stops answering, its bans are purged only after 7 days (we do not know whether they were lifted).

**Unban.** IP validated before any shell call, jail checked against the existing jails, fail2ban's answer checked (sudo may write a warning before the number). For Jeedom, the IP's failure counter is cleared too: otherwise a single new failure would ban it again at once. The ban is removed from memory and the alert recomputed immediately (otherwise the 8 am report would read the 7 am alert that still names this IP). Each unban is logged.
**Clear the alert**: for a ban already lifted that stays in the alert; also works when fail2ban stops answering.

## 9. "Probably you" and the alert

The morning alert (`alerte_tentatives`, read by the 8 am report) only talks about **a banned IP that is probably you**. Why: dozens of bots are banned every day, that is the normal background noise; what matters is being warned when it is you or your app that is locked out.

An IP is "probably you" if:

- it is in your whitelist, or on your local network;
- or it is a **French** residential connection that only requested missing Jeedom scripts (an app or a browser), or that Jeedom banned for failed passwords without any suspicious attempt.

Never: an IP from the blacklist, a hosting provider, a scanner, a VPN, an unrecognized owner, nor an IP whose whois is not done yet. Why: the alert offers to unban, it must never offer that for a bot.

- An sshd or recidive ban alone only counts for the whitelist: your phone does not do SSH, bots do.
- If the IP also looked for something other than Jeedom (`.env`, backdoor…), the alert says so: to check before unbanning.
- The alert is dated from when the ban was first seen and says whether the ban is already lifted.

Accepted limits: a bot on a French home router that only tries passwords would pass for you (rare; remedy: blacklist). You from abroad, through a VPN or an unknown provider would not be recognized (remedy: whitelist).

## 10. The plugin's whitelist and blacklist

They neither ban nor unban anything: they only decide who is "probably you". They are not the Jeedom lists.

- **Format**: one IP or CIDR network per line, IPv4 or IPv6, `#` for a comment. The plugin has its own network reading (`couvre`, based on `inet_pton`): it does not use `netMatch` and its pitfalls (chapter 7).
- **Whitelist limited to a /24 (IPv4) or a /48 (IPv6)**. Why: a /48 is what a provider gives to a subscriber; beyond that, you would whitelist a whole provider and its bots would pass for you. A too-wide entry typed before 0.12 is ignored and reported on the page.
- **Blacklist without limit**: wider = more cautious.
- **An IP in both lists is treated as blacklisted.**
- **Conflicts refused on save**: an added blacklist entry must cover neither the address you are saving from, nor an entry of your whitelist (it would cut off the alert that concerns you). An added whitelist entry must not be covered by the blacklist.
- **Only added entries are checked.** Why: an old entry (typed before a rule existed, or your 4G IP from last week that now covers something else) would otherwise block every new addition.
- The check goes through `preConfig_liste_blanche` and `preConfig_liste_noire`, which Jeedom calls on every save: an unreadable list is refused with a message instead of being silently ignored.

## 11. Learning and the `chemins_vises` rule

The error log only contains failures. **A successful attempt does not appear in it**: if a bot requests `/data/sauvegarde.txt` and the file exists, Apache serves it without writing anything to `http.error`. Hence the learning:

1. Every hour, the paths requested from outside (excluding the local network and Jeedom calls) are remembered: 1000 at most, the most recent.
2. During the audit, those that exist here are requested locally from Apache (`curl` on 127.0.0.1). A 200 answer means that anyone can read it.
3. Scripts executable by PHP (.php, .phtml, .phar…) are **never requested**: the request would execute them. Paths containing `..` are skipped.

**Backdoor.** A PHP script that was missing when a bot requested it, then present afterwards, is reported: this is the typical trace of an attacker who managed to drop their file and comes back to use it. The file is checked by its mere presence, never executed. It is excused if it was delivered normally:

- plugin: content older than the request (the market keeps the archive date);
- core (folders `core/`, `desktop/`, `mobile/`, `3rdparty/`, `vendor/`, `install/`, never `data/` nor the root): same modification date as `core/config/version` within 10 minutes, update done after the request.

The change date (ctime) is not used: Jeedom resets the permissions of all files on every update, so it would be the same everywhere. These scripts are forgotten after 90 days, so that a false alert eventually goes away.

Limits: an intruder who backdates their file goes through; a script published by a plugin after the request is reported wrongly (to check); a file restricted to the local network counts as served, since the request comes from 127.0.0.1. Apache only logs missing files (other than PHP) at `LogLevel info`; at the default `warn` level, only refusals and missing PHP scripts are in the log.

## 12. Equipment, widget, wizard

**Commands**: `score`, `problemes` (without the "info" items), `resume`, `graves` (titles of critical and high problems) and the `lancer` action. They are used in scenarios and in the morning report.

**Widget**: shown in the object chosen in the configuration ("Nowhere" or a deleted object hides it). The equipment is only moved if the choice changes: a placement done by hand stays. The "View the audit" button is only added on the dashboard, not in designs. The widget shows your weaknesses: put it in an object that only admins can see.

**Run from the widget or the API**: refused for a non-admin account, whether it goes through the browser or through the API with its user key. Why: the audit runs sudo commands for a minute. A scenario or a cron has no user and goes through. Limit: JeedomConnect does not pass on the user, so the app can run it.

**Wizard**: on the first visit after installation (or the 0.19 update), five questions that fill in the configuration (widget, whitelist, accepted ports, router checked, first audit). Prefilled with the current settings: running it again loses nothing. The whitelist is saved first: if it is refused, nothing else is changed. The checked ports are added to "Accepted ports", never removed. Why a wizard: without a whitelist or accepted ports, the first report is full of false problems and the "probably you" alert does not recognize you on 4G.

## 13. Stored data

| Data | Where | Duration, size | Why |
|---|---|---|---|
| Audit report | config `rapport` | last audit | page, commands, comparison for messages |
| Summary and alert | config `tentatives` | recomputed every hour | separate key: the morning report reads the alert without rerunning the audit |
| Attempts per IP | `data/historique.json` | 30 days, 500 IPs | the Jeedom log only keeps a few hundred lines |
| Whois | config `whois` | 30 days (1 day if silent), 300 IPs | whois is slow: never on display |
| Seen bans | config `bans_vus` | 30 h (more if active, 7 days if fail2ban silent) | morning alert, short bans |
| Learned paths | config `chemins_appris` | 1000 paths | `chemins_vises` rule |
| Missing scripts | config `scripts_absents` | 90 days | backdoor detection |
| Fix backups | `data/sauvegardes.json` and `secaudit` log | no limit | rolling back |
| Downloaded vulnerabilities | `data/checks_remote.json` | replaced every night | CVE rules |

Uninstalling removes all these configuration keys. The plugin's `data/` files disappear with it.

## 14. Requirements, test, limits

**Requirements**: passwordless `sudo` for www-data (standard Jeedom installation), the `whois` command, fail2ban for the bans part. Without sudo, the rules concerned go to "error" or see nothing; the rest works.

**Test**: `sudo -u www-data php tests/selftest.php` from the plugin folder (refused as root: the files created would belong to root and the cron could no longer write them). It checks the safeguard of the remote database, the reading of bans, log and lists, the alert, the display of this document, then evaluates each rule without saving a report. It stops at the first failure (`ECHEC : …`). Why not `assert()`: it is disabled in production.

**Known limits** (taken from the `ponytail:` comments in the code):

- NVD database: only the upper bound of the versions is read;
- history: marker to the second, a line written in the same second as a run can be lost;
- seen bans: configuration read then rewritten without a lock, at worst one reading lost and caught up 5 minutes later;
- "probably you": heuristic, corrected by the lists;
- `chemins_vises`: backdated file, file restricted to local, Apache log level;
- `fichiers_publics`: root of `data/` only (`data/custom` and `data/customTemplates` are served on purpose);
- the plugin sees neither the router, nor the host of a VM, nor what goes outside Apache.
