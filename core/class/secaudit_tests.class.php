<?php
/* Tests intégrés (règles de type « builtin ») : chacun renvoie [problème ?, détail]. */
class secaudit_tests {
  public static function test_admins_sans_2fa() {
    $l = [];
    foreach (user::all() as $u) if ($u->getEnable() && $u->getProfils() == 'admin' && $u->getOptions('twoFactorAuthentification', 0) != 1) $l[] = $u->getLogin();
    return [count($l) > 0, implode(', ', $l)];
  }

  public static function test_comptes_desactives() {
    $l = [];
    foreach (user::all() as $u) if (!$u->getEnable()) $l[] = $u->getLogin();
    return [count($l) > 0, implode(', ', $l)];
  }

  public static function test_certificat_expire() {
    $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false]]);
    $s = @stream_socket_client('ssl://127.0.0.1:443', $no, $err, 5, STREAM_CLIENT_CONNECT, $ctx);
    if (!$s) return [false, __('pas de HTTPS local', __FILE__)];
    $c = openssl_x509_parse(stream_context_get_params($s)['options']['ssl']['peer_certificate']);
    $jours = (int)floor(($c['validTo_time_t'] - time()) / 86400);
    return [$jours < 21, sprintf(__('expire le %s (%s j)', __FILE__), date('d/m/Y', $c['validTo_time_t']), $jours)];
  }

  // Entrée de security::whiteips plus large qu'un /24, lue comme netMatch de Jeedom (espaces retirés, pas les tabulations ; étoiles comptées, « /08 » = /8).
  // IPv6 : adresse exacte seulement. netMatch ne sait pas lire un réseau IPv6 : étoile ou plage = tout l'IPv6, préfixe > 32 = erreur PHP
  public static function large($e) {
    // comme netMatch : adresse exacte comparée après trim, puis seuls les espaces retirés (une tabulation au milieu fausse sa lecture : signalé)
    if (filter_var(trim($e), FILTER_VALIDATE_IP)) return trim($e) == '0.0.0.0';
    $e = str_replace(' ', '', $e);
    if (trim($e) === '' || in_array($e, ['127.0.0.0/8', '127.*.*.*'], true)) return false;
    if (strpos($e, ':') !== false) return !filter_var($e, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    // D : « $ » n'accepte pas un saut de ligne final (masque + \n = erreur PHP dans netMatch)
    // chaque adresse doit être valide : ip2long d'une borne illisible (192.168.1.01) donne une plage qui part de 0.0.0.0, un masque illisible une erreur PHP
    $v4 = fn($x) => (bool)filter_var($x, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    if (strpos($e, '*') !== false) return !(preg_match('/^(.+)\.\*$/D', $e, $m) && $v4("$m[1].0"));
    if (preg_match('/^(.+)-(.+)$/D', $e, $m)) return !($v4($m[1]) && $v4($m[2]) && ip2long($m[1]) >> 8 == ip2long($m[2]) >> 8);
    if (preg_match('#^(.+)/(\d+)$#D', $e, $m)) return !$v4($m[1]) || $m[2] < 24 || $m[2] > 32;
    if (preg_match('#^(.+)/(255\.255\.255\..+)$#D', $e, $m)) return !($v4($m[1]) && $v4($m[2]));
    return !$v4($e) || $e == '0.0.0.0'; // illisible, /-1, 0.0.0.0… : signalé
  }

  public static function test_whiteips_large() {
    $l = array_filter(explode(';', (string)config::byKey('security::whiteips')), 'secaudit_tests::large');
    return [(bool)$l, implode(' ; ', $l)];
  }

  public static function test_maj_jeedom() {
    $n = update::nbNeedUpdate();
    return [$n > 0, sprintf(__('%s en attente', __FILE__), $n)];
  }

  public static function test_maj_securite_debian() {
    $l = array_filter(explode("\n", (string)shell_exec('apt-get -s upgrade 2>/dev/null')), fn($x) => strpos($x, 'Inst ') === 0 && stripos($x, 'security') !== false);
    $noms = array_map(fn($x) => explode(' ', $x)[1], $l);
    return [count($noms) > 0, implode(', ', array_slice($noms, 0, 10))];
  }

  public static function fichiersPublics() {
    // ponytail: racine de data/ seulement ; data/custom et data/customTemplates sont servis exprès
    return glob('/var/www/html/data/*.{js,css,html,htm,txt}', GLOB_BRACE) ?: [];
  }

  public static function test_fichiers_publics() {
    $f = self::fichiersPublics();
    return [count($f) > 0, sprintf(__('%s fichier(s) : %s', __FILE__), count($f), implode(', ', array_map('basename', array_slice($f, 0, 8))))];
  }

  // Pas un problème : décrit sur quoi tourne Jeedom (affiché en tête du rapport, utile pour lire les autres points)
  public static function test_plateforme() {
    $virt = trim((string)shell_exec('systemd-detect-virt 2>/dev/null')) ?: 'none';
    $modele = is_file('/proc/device-tree/model') ? trim(file_get_contents('/proc/device-tree/model'), "\0\n") : '';
    $type = is_file('/.dockerenv') ? __('conteneur Docker', __FILE__) : ($virt != 'none' ? sprintf(__('machine virtuelle (%s)', __FILE__), $virt) : ($modele ?: __('machine physique', __FILE__)));
    $os = trim((string)shell_exec('. /etc/os-release 2>/dev/null && echo $PRETTY_NAME'));
    return [false, "$type, $os, " . php_uname('m') . ', PHP ' . PHP_VERSION . ', Jeedom ' . jeedom::version()];
  }

  // Ports en écoute sur toutes les interfaces, hors liste « ports_ok » (config du plugin : numéros de port ou noms de processus, ex. homebridge dont le port HomeKit change) ; 3306 et 8091 ont leur propre règle
  public static function test_ports_ouverts() {
    $ok = array_map('trim', explode(',', config::byKey('ports_ok', 'secaudit', '22,80,443,1883,8883,3306,8091')));
    $l = [];
    foreach (explode("\n", (string)shell_exec('sudo -n ss -tlnpH 2>/dev/null')) as $x) {
      if (!preg_match('/(?:0\.0\.0\.0|\*|\[::\]):(\d+)\s.*?(?:users:\(\("([^"]+)"|$)/', $x, $m) || in_array($m[1], $ok) || in_array($m[2] ?? '', $ok)) continue;
      $l[$m[1]] = $m[1] . (isset($m[2]) && $m[2] !== '' ? ' ' . $m[2] : '');
    }
    ksort($l);
    return [count($l) > 0, implode(', ', $l)];
  }

  public static function test_rappel() {
    return [config::byKey('box_ok', 'secaudit', 0) != 1, ''];
  }

  // Un chemin visé par les robots existe-t-il chez nous et est-il servi ? Fichiers que mod_php n'exécute pas seulement (.php, .phtml, .phar…).
  // ponytail: requête depuis 127.0.0.1 → un fichier réservé au local (Require local) compterait comme servi : faux positif, à vérifier de l'extérieur
  public static function test_chemins_vises() {
    $appris = secaudit_apprentissage::appris();
    $servis = [];
    $presents = 0;
    foreach (array_keys($appris) as $c) {
      $f = '/var/www/html' . $c;
      if (strpos($c, '..') !== false || !file_exists($f) || preg_match('/\.ph(p\d?|tml|ar|ps)$/i', $c) || is_file("$f/index.php")) continue;
      $presents++;
      $url = 'http://127.0.0.1' . implode('/', array_map('rawurlencode', explode('/', $c)));
      if (trim((string)shell_exec('curl -s -o /dev/null -m 5 -w "%{http_code}" ' . escapeshellarg($url))) == '200') $servis[] = $c;
    }
    // Script absent quand un robot l'a demandé, présent maintenant : vérifié par is_file seulement, jamais exécuté.
    // Excusé par la date de modification (mtime), jamais par le ctime : la réparation des droits de Jeedom (chown -R à chaque mise à jour) le remet partout.
    // Plugin : le market décompresse en gardant la date de l'archive → contenu plus ancien que la demande = livré.
    // Core (ses dossiers seulement, pas data/ ni la racine) : la mise à jour recopie tout à la même seconde que core/config/version → même mtime à 10 min près, après la demande = mise à jour.
    // ponytail: un intrus qui antidate son fichier (touch -d) passe ; un script publié par un plugin après la demande est signalé à tort (à vérifier)
    $apparus = [];
    $maj = @filemtime('/var/www/html/core/config/version');
    foreach (secaudit_apprentissage::absents() as $c => $t) {
      $f = '/var/www/html' . $c;
      if (strpos($c, '..') !== false || !is_file($f)) continue;
      $m = filemtime($f);
      if (strpos($c, '/plugins/') === 0 ? $m < $t : (preg_match('#^/(core|desktop|mobile|3rdparty|vendor|install)/#', $c) && $maj > $t && abs($m - $maj) <= 600)) continue;
      $apparus[] = $c;
    }
    $d = [];
    if ($servis) $d[] = sprintf(__('servis : %s', __FILE__), implode(', ', $servis));
    if ($apparus) $d[] = sprintf(__('absents quand un robot les a demandés, présents maintenant (porte dérobée ?) : %s', __FILE__), implode(', ', $apparus));
    return [(bool)($servis || $apparus), $d ? implode(' — ', $d) : sprintf(__('%s chemins visés retenus, %s présents ici, aucun servi, aucun script apparu', __FILE__), count($appris), $presents)];
  }
}
