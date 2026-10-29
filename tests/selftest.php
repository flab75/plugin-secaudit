<?php
/* Essai à blanc : évalue chaque règle sans enregistrer de rapport (met à jour l'historique, les bans vus et l'apprentissage, comme le cron).
   Usage : sudo -u www-data php tests/selftest.php (en root, data/historique.json appartiendrait à root et le cron ne pourrait plus l'écrire).
   Langue : sudo -u www-data php tests/selftest.php en_US (textes générés dans cette langue ; les contrôles sur le texte français tournent en fr_FR). */
if (function_exists('posix_getuid') && posix_getuid() === 0) exit("À lancer en www-data : sudo -u www-data php " . __FILE__ . "\n");
require_once __DIR__ . '/../core/class/secaudit.class.php';
$langue = $argv[1] ?? translate::getLanguage();
translate::setLanguage($langue);

// Garde-fou : une base distante ne doit jamais pouvoir ajouter de shell ni de correctif (fichier temporaire, le vrai n'est pas touché)
$ok = function ($v, $m) { if (!$v) { echo "ECHEC : $m\n"; exit(1); } }; // assert() est désactivé en production (zend.assertions=-1)
if ($langue == 'en_US') {
  $ok(secaudit_resume::texte([], 0) == 'No suspicious attempts in the log.', 'texte généré non traduit en anglais (core/i18n/en_US.json)');
  echo "traduction anglaise OK\n";
}
$f = tempnam(sys_get_temp_dir(), 'secaudit');
file_put_contents($f, json_encode(['checks' => [
  ['id' => 'pirate', 'type' => 'shell', 'cmd' => 'id', 'regex' => '/./', 'gravite' => 'haute', 'titre' => 'x'],
  ['id' => 'api_http', 'gravite' => 'info', 'fix' => 'whiteips', 'cmd' => 'id', 'titre' => 'renommé<img src=x onerror=alert(1)>', 'reference' => 'javascript:alert(1)'],
  ['id' => 'nouveau', 'type' => 'config', 'key' => 'x', 'op' => 'empty', 'gravite' => 'info', 'titre' => 'n<img src=x onerror=alert(1)>', 'fix' => 'whiteips', 'reference' => 'javascript:alert(1)'],
  ['id' => 'incomplet', 'type' => 'config', 'gravite' => 'info', 'titre' => 'sans clé'], ['id' => 'op', 'type' => 'config', 'key' => 'x', 'op' => 'system', 'value' => 1, 'gravite' => 'info', 'titre' => 't'],
  ['id' => 'cv', 'type' => 'core_version', 'gravite' => 'info', 'titre' => 't'],
  ['id' => ['x'], 'gravite' => 'info'], ['id' => 'y', 'gravite' => ['info']], 'texte', ['id' => 'api_tts', 'gravite' => 'info', 'titre' => ['x']],
  ['id' => 'whiteips_large', 'gravite' => 'critique'],
]]));
$c = secaudit_regles::checks($f);
unlink($f);
$ok(!isset($c['pirate']), 'shell distant accepté');
$ok($c['api_http']['fix'] == 'api_whiteip' && $c['api_http']['type'] == 'config' && !isset($c['api_http']['cmd']), 'règle locale altérée');
$ok(strpos($c['api_http']['titre'], 'renommé') === false && !isset($c['api_http']['reference']), 'texte d\'une règle locale réécrit par la base distante');
$ok($c['nouveau']['titre'] == 'n', 'HTML distant gardé');
$ok(!isset($c['incomplet']) && !isset($c['op']) && !isset($c['cv']), 'règle distante incomplète acceptée');
$ok($c['api_http']['gravite'] == 'haute' && $c['api_tts']['gravite'] == 'moyenne', 'gravité adoucie par la base distante');
$ok($c['whiteips_large']['gravite'] == 'critique', 'gravité aggravée par la base distante ignorée');
$ok(!isset($c['nouveau']['reference']), 'lien javascript: accepté');
$ok(!isset($c['y']) && is_string($c['api_tts']['titre']), 'champ distant non texte accepté');
$ok(isset($c['nouveau']) && !isset($c['nouveau']['fix']), 'ajout distant incorrect');
echo "garde-fou OK\n";

$x = secaudit_bans::lireBanip("203.0.113.42 \t2026-10-14 08:00:00 + 28800 = 2026-10-14 16:00:00");
$ok($x == ['ip' => '203.0.113.42', 'debut' => '2026-10-14 08:00:00', 'fin' => '2026-10-14 16:00:00'], 'lecture banip');
$ok(secaudit_bans::lireBanip('Status for the jail') === null, 'ligne parasite lue comme ban');
$e = null; try { secaudit_bans::debannir('fail2ban', 'sshd', '1.2.3.4; reboot'); } catch (Exception $e) {}
$ok($e !== null, 'IP non validée');
$ok(secaudit_bans::lireIgnoreip("These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- 192.168.1.0/24\n`- ::1\n") == '127.0.0.0/8 192.168.1.0/24 ::1', 'lecture ignoreip');
echo "bannissements OK\n";
$e = secaudit_tests::ecoutes("LISTEN 0 4096 *:3306 *:* users:((\"mariadbd\",pid=816,fd=5),(\"systemd\",pid=1,fd=73))\nLISTEN 0 4096 127.0.0.1:8099 0.0.0.0:* users:((\"docker-proxy\",pid=1,fd=8))\n"
  . "LISTEN 0 100 0.0.0.0:8883 0.0.0.0:* users:((\"mosquitto\",pid=662,fd=6))\nLISTEN 0 100 [::]:8883 [::]:* users:((\"mosquitto\",pid=662,fd=7))\nLISTEN 0 511 *:8091 *:*");
$ok($e == [3306 => ['mariadbd', 'systemd'], 8883 => ['mosquitto'], 8091 => []], 'lecture de ss');
$ok(secaudit_tests::ecoutesMqtt("LISTEN 0 100 0.0.0.0:1883 0.0.0.0:* users:((\"mosquitto\",pid=662,fd=5))\nLISTEN 0 100 [::]:1883 [::]:* users:((\"mosquitto\",pid=662,fd=8))\n"
  . "LISTEN 0 100 127.0.0.1:1884 0.0.0.0:* users:((\"mosquitto\",pid=662,fd=9))\nLISTEN 0 100 192.168.1.5:8883 0.0.0.0:* users:((\"mosquitto\",pid=662,fd=6))\nLISTEN 0 100 192.168.1.5:1885 0.0.0.0:* users:((\"mosquitto\",pid=662,fd=7))\n"
  . "LISTEN 0 4096 *:3306 *:*\nLISTEN 0 4096 [::1]:1883 [::]:*\nLISTEN 0 4096 0.0.0.0:1890 0.0.0.0:* users:((\"docker-proxy\",pid=9,fd=4))\nLISTEN 0 4096 0.0.0.0:1891 0.0.0.0:* users:((\"docker-proxy\",pid=9,fd=5))\n"
  . "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"docker-proxy\",pid=9,fd=6))", [1890 => ['nom' => 'mq', 'image' => 'eclipse-mosquitto:2', 'interne' => 1883],
    1891 => ['nom' => 'em', 'image' => 'emqx/emqx:5', 'interne' => 1891], 8080 => ['nom' => 'z2m', 'image' => 'koenkk/zigbee2mqtt', 'interne' => 8080]])
  == [['127.0.0.1', 1883], ['::1', 1883], ['192.168.1.5', 1885], ['127.0.0.1', 1890], ['127.0.0.1', 1891]], 'ports MQTT à sonder');
$ok(secaudit_tests::ecoutesMqtt("LISTEN 0 100 [::]:1883 [::]:* users:((\"mosquitto\",pid=662,fd=8))") == [['::1', 1883]], 'écoute MQTT IPv6 seule');
$ok(secaudit_tests::connack("\x20\x02\x00\x00") === 0 && secaudit_tests::connack("\x20\x02\x00\x05") === 5 && secaudit_tests::connack("\x15\x03\x01\x00") === null && secaudit_tests::connack('') === null, 'lecture du CONNACK MQTT');
$ok(secaudit_tests::conteneurs("signal|bbernhard/signal-cli-rest-api:0.81|0.0.0.0:8099->8080/tcp, :::8099->8080/tcp\nlocal|x|127.0.0.1:9000->9000/tcp\nsans|y|\nplage|z|0.0.0.0:8000-8002->9000-9002/tcp")
  == [8099 => ['nom' => 'signal', 'image' => 'bbernhard/signal-cli-rest-api:0.81', 'interne' => 8080], 9000 => ['nom' => 'local', 'image' => 'x', 'interne' => 9000],
      8000 => ['nom' => 'plage', 'image' => 'z', 'interne' => 9000], 8001 => ['nom' => 'plage', 'image' => 'z', 'interne' => 9001], 8002 => ['nom' => 'plage', 'image' => 'z', 'interne' => 9002]], 'lecture de docker ps');
$ok(secaudit_tests::clesSsh("== /root/.ssh/authorized_keys\nssh-ed25519 AAAA x\n# commentaire\n\n== /home/m1/.ssh/authorized_keys\nssh-rsa AAAA a\nssh-rsa AAAA b\n== /home/vide/.ssh/authorized_keys")
  == ['root' => 1, 'm1' => 2], 'clés SSH par compte');
$ok(secaudit_tests::connexionsMdp("sshd[1]: Accepted password for m1 from 192.168.1.200 port 1 ssh2\nsshd[2]: Accepted publickey for m1 from 192.168.1.9 port 2 ssh2\nsshd[3]: Accepted password for m1 from 192.168.1.200 port 3 ssh2\nsshd[4]: Failed password for root from 1.2.3.4 port 4 ssh2")
  == ['m1' => ['192.168.1.200']], 'connexions SSH par mot de passe');
$ok(secaudit_tests::lignesManquantes("ServerTokens Prod\n# x\n<Directory /var/www/html>\nOptions -Indexes\n</Directory>\n\n<IfModule a>\n</IfModule>", "ServerTokens   Prod\n<Directory /var/www/html>\n</Directory>\nTraceEnable On")
  == ['Options -Indexes', '<IfModule a>', '</IfModule>'], 'lignes manquantes de security.conf');
$ok(secaudit_tests::lignesManquantes("a\n# b\n", " a \n") == [], 'security.conf identique');
$ok(secaudit_tests::lignesManquantes("<IfModule a>\nphp x\n</IfModule>\n<IfModule b>\nphp x\n</IfModule>", "<IfModule a>\n</IfModule>\n<IfModule b>\nphp x\n</IfModule>") == ['php x'], 'ligne répétée retirée d\'un seul bloc');
$ligne = "RequestHeader set X-Forwarded-For \"expr=%{REMOTE_ADDR}\"\nRequestHeader unset X-Real-IP\nRequestHeader unset CF-Connecting-IP\nRequestHeader unset Client-IP\n";
$ancien = "RequestHeader unset X-Forwarded-For early\nRequestHeader unset X-Real-IP early\nRequestHeader unset CF-Connecting-IP early\nRequestHeader unset Client-IP early\n";
$ok(secaudit_tests::entetes($ligne) == [] && secaudit_tests::entetes($ligne, 'X-Forwarded-For') == [], 'en-têtes : correction 0.29 refusée');
$ok(secaudit_tests::entetes($ancien) == [] && count(secaudit_tests::entetes($ancien, 'X-Forwarded-For')) == 1, 'en-têtes : ancienne correction (early) mal lue avec ou sans proxy déclaré');
$ok(count(secaudit_tests::entetes($ligne . "RequestHeader unset X-Forwarded-For early\n", 'X-Forwarded-For')) == 1, 'en-têtes : unset early masqué par la réécriture');
$ok(count(secaudit_tests::entetes($ancien, 'CF-Connecting-IP')) == 1 && secaudit_tests::entetes($ligne . "RequestHeader unset X-Forwarded-For early\n", 'CF-Connecting-IP') == [], 'en-têtes : en-tête de remoteip autre que X-Forwarded-For');
$ok(count(secaudit_tests::entetes('')) == 4 && count(secaudit_tests::entetes("<IfModule mod_headers.c>\n  RequestHeader set X-Forwarded-For \"expr=%{REMOTE_ADDR}\"\n</IfModule>")) == 3, 'en-têtes : manques non comptés');
$early = str_replace('REMOTE_ADDR}"', 'REMOTE_ADDR}" early', $ligne);
$ok(secaudit_tests::entetes($early) == [] && count(secaudit_tests::entetes($early, 'X-Forwarded-For')) == 1 && count(secaudit_tests::entetes($early, 'X-Real-IP')) == 1, 'en-têtes : réécriture early mal jugée');
$ok(secaudit_tests::entetes(str_replace('"', "'", $ligne)) == [], 'en-têtes : guillemets simples refusés');
$ok(count(secaudit_tests::entetes('#' . str_replace("\n", "\n#", $ligne))) == 4 && count(secaudit_tests::entetes(str_replace('unset X-Real-IP', 'unset X-Real-IPv6', $ligne))) == 1, 'en-têtes : ligne commentée ou autre en-tête accepté');
$ok(secaudit_tests::remoteipConf("<IfModule mod_remoteip.c>\n  RemoteIPHeader X-Forwarded-For\n</IfModule>") == ['entete' => 'X-Forwarded-For', 'proxys' => []], 'remoteip sans proxy');
$ok(secaudit_tests::remoteipConf("RemoteIPHeader CF-Connecting-IP\n  RemoteIPInternalProxy 192.168.1.10\n# RemoteIPTrustedProxy 203.0.113.1\nRemoteIPTrustedProxyList conf/proxys.txt") == ['entete' => 'CF-Connecting-IP', 'proxys' => ['192.168.1.10', 'conf/proxys.txt']], 'remoteip : proxys déclarés');
$ok(secaudit_tests::remoteipConf("# RemoteIPHeader X-Forwarded-For") == ['entete' => '', 'proxys' => []], 'remoteip commenté');
$ss = "ESTAB 0 0 [::ffff:192.168.1.202]:443 [::ffff:203.0.113.7]:65175 users:((\"apache2\",pid=1234,fd=9))\n"
  . "ESTAB 0 0 127.0.0.1:41000 127.0.0.1:3306 users:((\"apache2\",pid=123,fd=10))\n"
  . "ESTAB 0 0 [::ffff:127.0.0.1]:80 [::ffff:127.0.0.1]:50256 users:((\"apache2\",pid=123,fd=9))\n"
  . "ESTAB 0 0 192.168.1.202:443 203.0.113.8:5000 users:((\"nginx\",pid=12,fd=4))\n"
  . "ESTAB 0 0 127.0.0.1:9000 127.0.0.1:40000 users:((\"php-fpm8.2\",pid=77,fd=5))\n"
  . "ESTAB 0 0 [fe80::1]%eth0:443 [fe80::2]%eth0:5000 users:((\"httpd\",pid=5,fd=4),(\"httpd\",pid=6,fd=4))";
$ecoute = "LISTEN 0 511 *:80 *:*\nLISTEN 0 511 *:443 *:*\nLISTEN 0 80 127.0.0.1:3306 0.0.0.0:*\nLISTEN 0 511 127.0.0.1:9000 0.0.0.0:*";
$ok(secaudit_tests::connexion($ss, $ecoute, 1234) === '203.0.113.7' && secaudit_tests::connexion($ss, $ecoute, 123) === '127.0.0.1'
  && secaudit_tests::connexion($ss, $ecoute, 12) === null && secaudit_tests::connexion($ss, $ecoute, 77) === null
  && secaudit_tests::connexion($ss, $ecoute, 6) === 'fe80::2' && secaudit_tests::connexion($ss, $ecoute, 1) === null && secaudit_tests::connexion('', '', 1234) === null, 'adresse de connexion de la requête');
$ok(secaudit_tests::remoteipConf("RemoteIPHeader X-Forwarded-For\nRemoteIPHeader CF-Connecting-IP")['entete'] == 'CF-Connecting-IP', 'remoteip : dernière ligne RemoteIPHeader');
$q = fn($p, $id, $ip = '192.168.1.202') => "[2026-10-15 10:51:$id][INFO] { &quot;jsonrpc&quot;: &quot;2.0&quot;, &quot;id&quot;:$id, &quot;method&quot;: &quot;daemonIsReady&quot;, &quot;params&quot;:{ &quot;plugin&quot;: &quot;$p&quot;, &quot;apikey&quot;: &quot;k$p&quot;}} - IP :$ip";
$r = "[2026-10-15 10:51:%s][INFO] Error code 2 : Vous n&apos;êtes pas autorisé à effectuer cette action";
$rq = secaudit_tests::requetesApi(implode("\n", [$q('homebridge', 20), sprintf($r, 21), $q('z2m', 23), $q('homebridge', 24), sprintf($r, 25), $q('<b>', 26), sprintf($r, 27), $q('z2m', 28), sprintf($r, 29), $q('z2m', 30)]));
$ok(count($rq) == 6 && $rq[0]['quand'] == '2026-10-15 10:51:21' && $rq[0]['refuse'] && !$rq[1]['refuse'] && $rq[3]['plugin'] === '' && !$rq[5]['refuse'], 'requêtes de l\'API (refus rattaché, nom filtré)');
$c = secaudit_tests::clientsRefuses($rq, '2026-10-15 00:00:00');
$ok(count($c['clients']) == 1 && $c['clients'][0]['nb'] == 3 && $c['clients'][0]['quand'] == '2026-10-15 10:51:27' && $c['externes'] == []
  && $c['clients'][0]['clients'] == [['plugin' => 'homebridge', 'cle' => 'khomebridge', 'nb' => 2], ['plugin' => '', 'cle' => 'k<b>', 'nb' => 1]], 'refus regroupés par IP (z2m réparé = hors liste)');
$c = secaudit_tests::clientsRefuses(secaudit_tests::requetesApi(implode("\n", [$q('a', 10), sprintf($r, 11), $q('a', 12), $q('a', 13), sprintf($r, 14)])), '');
$ok($c['clients'][0]['nb'] == 1, 'refus remis à zéro par une requête acceptée');
$e = implode("\n", [$q('a1', 10, '1.2.3.4'), sprintf($r, 11), $q('a2', 12, '1.2.3.4'), sprintf($r, 13), $q('a3', 14, '1.2.3.4'), sprintf($r, 15), $q('a3', 16, '1.2.3.4')]);
$c = secaudit_tests::clientsRefuses(secaudit_tests::requetesApi($e), '2026-10-15 00:00:00');
$ok($c['clients'][0]['ip'] == '1.2.3.4' && $c['clients'][0]['nb'] == 2 && $c['externes'] == ['1.2.3.4' => 3], 'nom de plugin changé à chaque essai : compté par IP et en externe');
$ok(secaudit_tests::clientsRefuses(secaudit_tests::requetesApi($e), '2026-10-16 00:00:00')['externes'] == [], 'refus externes hors période');
$ok(secaudit_tests::requetesApi(sprintf($r, 21))[0]['ip'] == '?', 'refus sans requête journalisée');
$ok(secaudit_tests::requetesApi("[appelez le 06][INFO] Error code 2 : x\n[2026-10-15 10:51:2][INFO] Error code 2 : x\n[2026-10-15 10:51:20][INFO] Error code 21 : x") == [], 'refus fabriqué sans horodatage strict');
$rq = secaudit_tests::requetesApi("[2026-10-15 10:51:20][INFO] Demande sur l'api http venant de : 192.168.1.5 => {\"x\":\" : 192.168.1.202 => {\"}");
$ok(count($rq) == 1 && $rq[0]['ip'] == '192.168.1.5', 'IP du 2e format prise avant le JSON du client');
// corps sur 2 lignes : le refus ne va ni à la requête précédente, ni à la poubelle ; IP de la ligne de suite
$rq = secaudit_tests::requetesApi(implode("\n", [$q('a', 10), "[2026-10-15 10:51:11][INFO] {", "&quot;apikey&quot;:&quot;x&quot;} - IP :203.0.113.9", sprintf($r, 12), sprintf($r, 13)]));
$ok(count($rq) == 3 && !$rq[0]['refuse'] && $rq[1]['ip'] == '203.0.113.9' && $rq[1]['refuse'] && $rq[2]['ip'] == '?' && $rq[2]['refuse'], 'refus d\'une requête sur plusieurs lignes');
$c = secaudit_tests::clientsRefuses($rq, '');
$ok($c['clients'] == [] && $c['total'] == 2, 'orphelins comptés sur la période seulement');
// fausse requête dans un corps, suivie de la vraie fin de ligne : le refus va à l'IP réelle
$rq = secaudit_tests::requetesApi(implode("\n", ["[2026-10-15 10:51:10][INFO] {", $q('a', 11, '8.8.8.8'), "} - IP :203.0.113.9", sprintf($r, 12)]));
$ok(count($rq) == 2 && $rq[1]['ip'] == '203.0.113.9' && $rq[1]['refuse'] && !$rq[0]['refuse'], 'requête forgée dans un corps');
// autre code d'erreur : ni refus, ni remise à zéro
$c = secaudit_tests::clientsRefuses(secaudit_tests::requetesApi(implode("\n", [$q('a', 10), sprintf($r, 11), $q('a', 12), "[2026-10-15 10:51:13][INFO] Error code 1 : x", $q('a', 14), sprintf($r, 15)])), '');
$ok($c['clients'][0]['nb'] == 2 && $c['total'] == 2, 'erreur autre que la clé sans effet sur le compteur');
$c = secaudit_tests::clientsRefuses(secaudit_tests::requetesApi(implode("\n", [$q('a', 10, '100.100.1.2'), sprintf($r, 11), $q('a', 12, '203.0.113.9'), sprintf($r, 13)])), '');
$ok($c['externes'] == ['203.0.113.9' => 1] && $c['total'] == 2, 'Tailscale (100.64.0.0/10) hors refus d\'Internet');
echo "lecture des services OK\n";
$e = secaudit_journal::lireEssai("[Tue Oct 14 08:04:12.123 2026] [access_compat:error] [pid 1:tid 1] [client 87.58.199.133:5555] AH01797: client denied by server configuration: /var/www/html/.env.json");
$ok($e && $e['ip'] == '87.58.199.133' && $e['chemin'] == '/.env.json' && !$e['absent'] && date('Y-m-d H:i', $e['t']) == '2026-10-14 08:04', 'lecture refus');
$e = secaudit_journal::lireEssai("[Tue Oct 13 12:13:23.634602 2026] [php:error] [pid 1:tid 1] [client 203.0.113.42:62434] script '/var/www/html/core/ajax/planHeader.ajax.php' not found or unable to stat, referer: x");
$ok($e && $e['chemin'] == '/core/ajax/planHeader.ajax.php' && $e['absent'] && secaudit_journal::famille($e['chemin']) == 'jeedom', 'lecture script absent');
$ok(secaudit_journal::lireEssai('[Tue Oct 13 11:21:09.5 2026] [php:warn] [client 1.2.3.4:1] PHP Warning: x') === null, 'avertissement PHP lu comme essai');
$ok(secaudit_journal::lireEssai("[Tue Oct 13 11:21:09.5 2026] [php:warn] [pid 1] [client 6.6.6.6:1] PHP Warning: x, referer: [client 192.168.1.20:1] script '/var/www/html/core/ajax/x.ajax.php'") === null, 'essai fabriqué par le referer');
$e = secaudit_journal::lireEssai("[Tue Oct 14 08:04:12.1 2026] [authz_core:error] [pid 1:tid 1] [client 5.5.5.5:1] AH01630: client denied by server configuration: /var/www/html/data/x.json");
$ok($e && $e['ip'] == '5.5.5.5' && $e['chemin'] == '/data/x.json', 'lecture refus Require');
$e = secaudit_journal::lireEssai("[Tue Oct 14 08:04:12.1 2026] [core:info] [pid 1:tid 1] [client 5.5.5.5:1] AH00128: File does not exist: /var/www/html/x.txt");
$ok($e && $e['chemin'] == '/x.txt', 'lecture fichier absent');
foreach (['/core/.env' => 'secrets', '/plugins/z2m/data/database.db' => 'secrets', '/core/config/common.config.php' => 'secrets', '/mobile/' => 'jeedom', '/core/img/x.png' => 'jeedom', '/favicon.ico' => 'jeedom', '/plugins/secaudit/core/ajax/secaudit.ajax.php' => 'jeedom', '/plugins/pasinstalle/core/ajax/x.ajax.php' => 'autre', '/plugins/jquery-file-upload/server/php/index.php' => 'autre', '/core/x/y.php' => 'autre', '/.env' => 'secrets', '/shell.php' => 'portes', '/actuator' => 'diag', '/adminer.php' => 'admin', '/wp-content' => 'cms', '/mifs' => 'equip', '/xyz' => 'autre'] as $c => $f)
  $ok(secaudit_journal::famille($c) == $f, "famille $c");
$ok(strpos(secaudit_whois::profil('Palo Alto Networks, Inc'), 'sécurité') !== false && strpos(secaudit_whois::profil('Microsoft Corporation'), 'hébergeur') !== false
  && strpos(secaudit_whois::profil('Free SAS'), 'particulier') !== false && strpos(secaudit_whois::profil('Orange Business Services'), 'hébergeur') !== false && secaudit_whois::profil('ADISTA') == 'propriétaire non reconnu', 'profil');
translate::setLanguage('fr_FR'); // contrôles ci-dessous sur le texte français ; la langue demandée revient après « analyse OK »
$fr = ['profil' => 'connexion de particulier (machine probablement infectée)', 'pays' => 'FR'];
$l = [['ip' => '1.1.1.1', 'nb' => 2, 'qui' => $fr, 'familles' => ['jeedom'], 'jeedom_seul' => true, 'bans' => [['fin' => 'x']], 'bans_recents' => ['apache-noscript'], 'vu' => time(), 'liste' => ''],
      ['ip' => '2.2.2.2', 'nb' => 9, 'qui' => $fr, 'familles' => ['secrets'], 'jeedom_seul' => false, 'bans' => [['fin' => 'x']], 'bans_recents' => ['apache-noscript'], 'vu' => time(), 'liste' => '']];
$ok(strpos(secaudit_resume::alerte($l), '1.1.1.1 (vue bannie le') !== false && strpos(secaudit_resume::alerte($l), '2.2.2.2') === false, 'alerte : appli Jeedom bannie');
$ok(secaudit_resume::alerte([$l[1]]) === '', 'alerte sur un robot banni');
$ok(strpos(secaudit_resume::alerte([['liste' => 'blanche'] + $l[1]]), 'a aussi cherché : vol de secrets') !== false, 'alerte : liste blanche qui a cherché des secrets sans avertissement');
$j = ['ip' => '3.3.3.3', 'nb' => 0, 'qui' => $fr, 'familles' => [], 'jeedom_seul' => false, 'bans' => [['source' => 'jeedom', 'fin' => 'x']], 'bans_recents' => ['jeedom'], 'vu' => time(), 'liste' => ''];
$ok(secaudit_resume::alerte([$j]) !== '', 'alerte : banni par Jeedom depuis une box française (mots de passe)');
$ok(secaudit_resume::alerte([['qui' => ['profil' => 'propriétaire non reconnu', 'pays' => 'FR']] + $j]) === '', 'alerte : propriétaire non reconnu');
$ok(secaudit_resume::alerte([['qui' => ['profil' => 'whois muet (nouvel essai demain)']] + $j]) === '', 'alerte : whois muet');
$s = ['qui' => ['profil' => $fr['profil'], 'pays' => 'CN'], 'bans_recents' => ['sshd']] + $j;
$ok(secaudit_resume::alerte([$s]) === '', 'alerte sur un robot étranger');
$ok(secaudit_resume::alerte([['bans_recents' => ['sshd']] + $l[0]]) === '', 'alerte sur un ban sshd');
$ok(secaudit_resume::alerte([['bans_recents' => ['sshd'], 'liste' => 'blanche'] + $s]) !== '', 'alerte : liste blanche bannie par sshd');
$ok(secaudit_resume::alerte([['liste' => 'noire'] + $j]) === '', 'alerte sur la liste noire');
$ok(strpos(secaudit_resume::alerte([['bans' => []] + $j]), 'ban déjà levé') !== false, 'alerte : ban Jeedom levé avant le cron');
$ok(secaudit_resume::alerte([['qui' => ['profil' => 'hébergeur / cloud', 'pays' => 'FR']] + $l[0]]) === '', 'alerte sur un robot Jeedom hébergé');
$ok(secaudit_resume::alerte([['qui' => ['profil' => 'pas encore identifiée (whois chaque heure)']] + $l[0]]) === '', 'alerte avant le whois');
$ok(strpos(secaudit_resume::texte([['liste' => 'blanche'] + $l[1]], 0), '1 adresse(s) extérieure(s) ont sondé') !== false, 'résumé : liste blanche qui a cherché des secrets comptée comme vous');
$ok(strpos(secaudit_resume::texte([['liste' => 'blanche'] + $l[0]], 0), 'sans doute vous') !== false, 'résumé : liste blanche Jeedom seul');
foreach ([['1.2.3.4', '1.2.3.4', 1], ['1.2.3.0/24', '1.2.3.200', 1], ['1.2.3.0/24', '1.2.4.1', 0], ['1.2.0.0/15', '1.3.9.9', 1], ['1.2.0.0/15', '1.4.0.1', 0], ['0.0.0.0/0', '9.9.9.9', 1],
          ['2001:db8::/32', '2001:db8:90d::1', 1], ['2001:db8::/32', '2001:db9::1', 0], ['1.2.3.4', '::1', 0], ['1.2.3.4/40', '1.2.3.4', 0], ['abc', '1.2.3.4', 0]] as [$r, $ip, $att])
  $ok(secaudit_listes::couvre($r, $ip) == $att, "liste : $r couvre $ip");
$ok(secaudit_listes::entrees("1.2.3.4 # 4G\n\n5.6.7.0/24, 2a01::/16\n# rien") == ['1.2.3.4', '5.6.7.0/24', '2a01::/16'], 'lecture d\'une liste');
$e = null; try { secaudit_listes::verifier("1.2.3.4\nmaison"); } catch (Exception $e) {}
$ok($e !== null, 'liste illisible acceptée');
$e = null; try { secaudit_listes::verifier("1.2.3.0/33"); } catch (Exception $e) {}
$ok($e !== null, 'masque invalide accepté');
foreach (['10.0.0.0/8', '2a01:cb00::/24', '203.0.0.0/16', '2001:db8::/32'] as $v) { $e = null; try { secaudit_listes::verifier($v); } catch (Exception $e) {} $ok($e !== null, "réseau trop large accepté : $v"); }
$ok(secaudit_listes::verifier("203.0.113.0/24\n2001:db8:1::/48") !== '', 'réseau /24 ou /48 refusé');
$ok(secaudit_listes::verifier("198.18.0.0/15\n2001:db8::/32", false) !== '', 'liste noire large refusée');
$_SERVER['REMOTE_ADDR'] = '203.0.113.200'; $e = null; try { secaudit_listes::verifier("203.0.0.0/8", false); } catch (Exception $e) {} unset($_SERVER['REMOTE_ADDR']);
$ok($e !== null, 'liste noire qui couvre votre adresse acceptée');
// liste noire temporaire, seulement si la vraie est vide : remise par config::remove (pas de preConfig qui revérifierait),
// et $ok après la remise ($ok fait exit, qui saute finally)
if (trim(config::byKey('liste_noire', 'secaudit', '')) === '') {
  $e = $x = null;
  try {
    config::save('liste_noire', '203.0.113.0/24', 'secaudit');
    try { secaudit_listes::verifier("198.51.100.7\n203.0.113.7"); } catch (Exception $e) {}
    try { $x = secaudit_listes::verifier("198.51.100.7\n203.0.113.7", true, '203.0.113.7'); } catch (Exception $z) {}
  } finally { config::remove('liste_noire', 'secaudit'); }
  $ok($e !== null, 'liste blanche couverte par la liste noire acceptée');
  $ok($x !== null, 'ancienne entrée en conflit qui bloque un ajout');
} else echo "Liste noire non vide : test des conflits sauté\n";
$ok(secaudit_listes::tropLarge('203.0.0.0/8') && !secaudit_listes::tropLarge('203.0.113.200') && !secaudit_listes::tropLarge('2a01::1'), 'trop large (lecture d\'une liste de la 0.9)');
$ok(netMatch('127.0.0.0/8', '127.0.0.1') && netMatch('127.*.*.*', '127.0.0.1') && !netMatch('192.168.1.*', '127.0.0.1'), 'netMatch de Jeedom'); // « 127.* » ne marche pas : Jeedom compte les étoiles (1 = /24)
foreach (['127.0.0.1' => 0, '192.168.1.*' => 0, '192.168.*.*' => 1, '10.0.0.0/8' => 1, '192.168.1.0/24' => 0, '*' => 1, '192.*.1.*' => 1, '10.*' => 1, '192.168.1.0/23' => 1, '127.0.0.0/8' => 0,
          '0.0.0.0-255.255.255.255' => 1, '10.0.0.0/255.0.0.0' => 1, '192.168.1.0/255.255.255.0' => 0, '192.168.1.10-192.168.1.20' => 0, '0.0.0.0' => 1, '0.0.0.0/0' => 1,
          '127.0.0.1/0' => 1, '127.0.0.0/1' => 1, '127.0.0.1-255.255.255.255' => 1, '127.*.*.*' => 0, '::/0' => 1, '2001:db8::/32' => 1, '2001:db8:1::/56' => 1, '::1' => 0,
          '2001:db8:1:*' => 1, '2a01::1-2a01::2' => 1, '10.0.0.0 / 8' => 1, ' 127.0.0.1 /0' => 1, '10.0.0.0/08' => 1, '1.2.3.4/-1' => 1, '1.2.3.4/40' => 1, ' 192.168.1.20 ' => 0,
          '192.168.1.01-192.168.1.20' => 1, '192.168.1.300-192.168.1.255' => 1, '1.2.3.4/255.255.255.300' => 1, '1.2.3.400/24' => 1, '192.168.01.*' => 1, '192.168.1.*.*' => 1, '192.168.1.0/255.255.255.128' => 0,
          "\t192.168.1.20" => 0, "192.168.1.1\t-192.168.1.20" => 1, "1.2.3.0/2\t4" => 1, "1.2.3.0/255.255.255.0\n" => 1, "1.2.3.0/24\n" => 1] as $v => $att)
  $ok(secaudit_tests::large($v) == $att, "whiteips_large « $v »");
$ok(strpos(secaudit_resume::texte([['qui' => ['profil' => 'hébergeur / cloud']] + $l[0]], 0), '1 adresse(s) extérieure(s) ont sondé') !== false, 'résumé : robot Jeedom hébergé pris pour vous');
$ok(strpos(secaudit_resume::texte(array_merge($l, [$s]), 0), '1 adresse(s) extérieure(s) ont sondé') !== false, 'résumé : IP sans essai comptée');
$ok(strpos(secaudit_resume::texte($l, 0), '1 adresse(s) extérieure(s) ont sondé') !== false, 'résumé : appli comptée comme attaquant');
echo "analyse OK\n";
translate::setLanguage($langue);
$d = secaudit_doc::html("# T\n\n| a | b |\n|---|---|\n| `x` | <i> |\n- **g**\n  suite\n\ntexte");
$ok($d == '<h1>T</h1><table class="table table-condensed table-bordered"><tr><th>a</th><th>b</th></tr><tr><td><code>x</code></td><td>&lt;i&gt;</td></tr></table><ul><li><strong>g</strong> suite</ul><p>texte</p>', 'rendu de la documentation');
$ok(strpos(secaudit_doc::html(), '<h2>14. Prérequis') !== false, 'documentation absente ou illisible');
$ok(strpos(secaudit_doc::html((string)file_get_contents(__DIR__ . '/../docs/en_US/methodes.md')), '<h2>14. ') !== false, 'documentation anglaise absente ou illisible');
$ok(is_array(json_decode((string)file_get_contents(__DIR__ . '/../core/i18n/en_US.json'), true)), 'traduction en_US.json illisible');
echo "documentation OK\n";
$b = secaudit_tentatives::analyser();
echo $b['resume'], "\n", 'alerte : ', $b['alerte'], "\n", 'ignore : ', $b['ignore'], "\n";
foreach ($b['lignes'] as $x) printf("%-16s %-3d %-28s %-45s %s\n", $x['ip'], $x['nb'], mb_substr($x['qui']['org'], 0, 28), mb_substr($x['qui']['profil'], 0, 45), implode(',', $x['familles']));
echo 'non classés : ', implode(' ', $b['non_classes']), "\n";
echo 'appris : ', secaudit_apprentissage::apprendre(), "\n";

foreach (secaudit_regles::checks() as $c) {
  try { [$pb, $d] = secaudit_regles::evaluer($c); $e = $pb ? 'PROBLEME' : 'ok'; } catch (Throwable $x) { $e = 'ERREUR'; $d = $x->getMessage(); }
  printf("%-8s %-9s %-22s %s\n", $e, $c['gravite'], $c['id'], $d);
}
