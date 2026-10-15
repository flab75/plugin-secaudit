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

$x = secaudit_bans::lireBanip("94.127.15.189 \t2026-10-14 08:00:00 + 28800 = 2026-10-14 16:00:00");
$ok($x == ['ip' => '94.127.15.189', 'debut' => '2026-10-14 08:00:00', 'fin' => '2026-10-14 16:00:00'], 'lecture banip');
$ok(secaudit_bans::lireBanip('Status for the jail') === null, 'ligne parasite lue comme ban');
$e = null; try { secaudit_bans::debannir('fail2ban', 'sshd', '1.2.3.4; reboot'); } catch (Exception $e) {}
$ok($e !== null, 'IP non validée');
$ok(secaudit_bans::lireIgnoreip("These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- 192.168.1.0/24\n`- ::1\n") == '127.0.0.0/8 192.168.1.0/24 ::1', 'lecture ignoreip');
echo "bannissements OK\n";
$e = secaudit_journal::lireEssai("[Tue Oct 14 08:04:12.123 2026] [access_compat:error] [pid 1:tid 1] [client 87.58.199.133:5555] AH01797: client denied by server configuration: /var/www/html/.env.json");
$ok($e && $e['ip'] == '87.58.199.133' && $e['chemin'] == '/.env.json' && !$e['absent'] && date('Y-m-d H:i', $e['t']) == '2026-10-14 08:04', 'lecture refus');
$e = secaudit_journal::lireEssai("[Tue Oct 13 12:13:23.634602 2026] [php:error] [pid 1:tid 1] [client 94.127.15.189:62434] script '/var/www/html/core/ajax/planHeader.ajax.php' not found or unable to stat, referer: x");
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
