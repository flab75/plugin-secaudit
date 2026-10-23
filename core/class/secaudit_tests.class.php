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

  // Lignes de la configuration livrée par Jeedom absentes de celle d'Apache (espaces et commentaires ignorés).
  // Comptées avec leurs répétitions : les php_admin_* existent dans deux blocs <IfModule>, vider l'un doit se voir.
  // ponytail: lignes manquantes seulement ; une directive ajoutée ensuite qui en annule une (Options +Indexes) passe, casse comprise (copie exacte attendue)
  public static function lignesManquantes($ref, $actuel) {
    $n = fn($t) => array_count_values(array_filter(array_map(fn($x) => preg_replace('/\s+/', ' ', trim($x)), explode("\n", $t)), fn($x) => $x !== '' && $x[0] != '#'));
    $a = $n($actuel);
    return array_keys(array_filter($n($ref), fn($c, $x) => ($a[$x] ?? 0) < $c, ARRAY_FILTER_USE_BOTH));
  }

  // Jeedom 4.5+ recopie install/apache_security dans conf-available/security.conf (mise à jour, réparation) si celui-ci contient jeedom.com ; la 4.6.2 y ajoute les protections PHP.
  // Sinon seuls l'installation et le bouton « Apache sécurisé » (page Système) le recopient : l'écart vient en général des mises à jour, le constat le dit
  public static function test_apache_security() {
    $ref = '/var/www/html/install/apache_security';
    $f = '/etc/apache2/conf-enabled/security.conf'; // celle qu'Apache charge (lien vers conf-available d'habitude)
    if (!is_file($ref) || !is_dir('/etc/apache2')) return [false, ''];
    if (is_link($f) && !file_exists($f)) return [true, __('lien security.conf cassé : Apache refusera de redémarrer', __FILE__)];
    if (!file_exists($f)) return [true, __('security.conf désactivé', __FILE__)];
    if (!is_readable($f)) throw new Exception(__('security.conf illisible', __FILE__));
    $c = (string)file_get_contents($f);
    $l = self::lignesManquantes((string)file_get_contents($ref), $c);
    if (!$l) return [false, ''];
    $d = sprintf(__('%s ligne(s) absente(s) : %s', __FILE__), count($l), implode(' ; ', array_slice($l, 0, 5)));
    if (!is_link($f)) return [true, __('security.conf de conf-enabled n\'est pas un lien : Jeedom met à jour celui de conf-available', __FILE__) . ' ; ' . $d];
    if (version_compare(jeedom::version(), '4.5', '<')) return [true, __('Jeedom < 4.5 ne recopie pas ce fichier lors des mises à jour', __FILE__) . ' ; ' . $d];
    if (strpos($c, 'jeedom.com') === false) return [true, __('security.conf sans jeedom.com : Jeedom ne le recopie pas lors des mises à jour', __FILE__) . ' ; ' . $d];
    return [true, $d];
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

  // Sortie de ss mise en commun par les règles de ports (une seule commande par audit). Sans sudo, ss sans -p : ports vus, processus non
  private static function ss() {
    static $s = null;
    return $s ??= (string)shell_exec('sudo -n ss -tlnpH 2>/dev/null || ss -tlnH 2>/dev/null');
  }

  // Ports en écoute sur toutes les interfaces : [port => [processus…]], IPv4 et IPv6 fusionnés (les adresses précises, 127.0.0.1 comprise, sont ignorées)
  public static function ecoutes($ss) {
    $l = [];
    foreach (explode("\n", $ss) as $x) {
      if (!preg_match('/\s(?:0\.0\.0\.0|\*|\[::\]):(\d+)\s/', $x, $m)) continue;
      preg_match_all('/\("([^"]+)",/', $x, $p);
      $l[$m[1]] = array_values(array_unique(array_merge($l[$m[1]] ?? [], $p[1])));
    }
    return $l;
  }

  // `docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}'` : [port publié => [nom, image, port interne]]. Plage 8000-8010->9000-9010 : chaque port (1 000 au plus)
  public static function conteneurs($ps) {
    $l = [];
    foreach (explode("\n", $ps) as $x) {
      $c = explode('|', $x);
      if (count($c) == 3 && preg_match_all('/:(\d+)(?:-(\d+))?->(\d+)/', $c[2], $m, PREG_SET_ORDER))
        foreach ($m as [, $a, $b, $i]) foreach (range($a, min(max($a, (int)$b), $a + 999)) as $p) $l[$p] = ['nom' => $c[0], 'image' => $c[1], 'interne' => $i + $p - $a];
    }
    return $l;
  }

  // Code HTTP d'une requête sans mot de passe sur 127.0.0.1 ('000' : pas du HTTP, ou pas d'écoute en IPv4). $port vient de ecoutes() : chiffres seulement
  private static function http($port, $chemin = '/') {
    return trim((string)shell_exec('curl -s -o /dev/null --connect-timeout 1 -m 2 -w "%{http_code}" ' . escapeshellarg("http://127.0.0.1:$port$chemin")));
  }

  // Ports en écoute sur toutes les interfaces, hors liste « ports_ok » (config du plugin : numéros de port ou noms de processus, ex. homebridge dont le port HomeKit change) ; 3306 et 8091 ont leur propre règle.
  // Conteneur Docker : nom, image, équipement Docker management. Puis une requête HTTP sans mot de passe dit si le service est ouvert à tous.
  // ponytail: chemin propre à une image connue (l'API Signal ne répond pas sur /) ; ajouter une image ici quand un cas se présente
  const CHEMINS = ['signal-cli-rest-api' => '/v1/about'];
  // Seuls ces processus reçoivent la requête HTTP : un pont série (ser2net, socat) ou le socket d'un démon de plugin recevrait des octets qu'il ne comprend pas.
  // ponytail: liste de serveurs web courants ; un service web d'un autre nom n'est pas sondé (constat sans « mot de passe »), l'ajouter ici
  const WEB = ['node', 'nginx', 'lighttpd', 'apache2', 'httpd', 'caddy', 'traefik'];
  // Conteneur : sondé si son image est dans CHEMINS ou si son port interne est un port web courant. ponytail: liste à compléter au besoin
  const WEB_INTERNES = [80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000];
  // Liste brute, sans requête (lue aussi par l'assistant à chaque visite de la page) : [port => processus]
  public static function portsOuverts() {
    $ok = array_map('trim', explode(',', config::byKey('ports_ok', 'secaudit', '22,80,443,1883,8883,3306,8091')));
    return array_filter(self::ecoutes(self::ss()), fn($procs, $port) => !in_array((string)$port, $ok, true) && !array_intersect($procs, $ok), ARRAY_FILTER_USE_BOTH);
  }

  public static function test_ports_ouverts() {
    $l = [];
    $docker = null;
    foreach (self::portsOuverts() as $port => $procs) {
      $t = trim("$port " . implode('/', $procs));
      $chemin = '/';
      $web = false;
      if (in_array('docker-proxy', $procs)) {
        $docker ??= self::conteneurs((string)shell_exec("timeout 10 sudo -n docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null"));
        if ($c = $docker[$port] ?? null) {
          $t = sprintf(__('%s conteneur %s (%s)', __FILE__), $port, $c['nom'], $c['image']);
          $web = in_array($c['interne'], self::WEB_INTERNES);
          foreach (self::CHEMINS as $i => $ch) if (strpos($c['image'], $i) !== false) [$chemin, $web] = [$ch, true];
          if (class_exists('docker2')) foreach (eqLogic::byType('docker2') as $e)
            if (substr($e->getLogicalId(), -strlen("::$c[nom]")) === "::$c[nom]") $t .= sprintf(__(', équipement Docker management « %s »', __FILE__), $e->getName());
        }
      }
      // ponytail: 2xx sur / prouve seulement qu'une page est servie (un formulaire de connexion répond 200 aussi) ; « sans mot de passe » seulement sur un chemin d'API connu
      $code = array_intersect($procs, self::WEB) || $web ? self::http($port, $chemin) : '';
      if (substr($code, 0, 1) === '2') $t .= $chemin !== '/' ? __(' : répond sans mot de passe', __FILE__) : sprintf(__(' : page web servie (HTTP %s), vérifier si elle demande un mot de passe', __FILE__), $code);
      elseif (in_array($code, ['401', '403'])) $t .= __(' : demande un mot de passe', __FILE__);
      elseif ($code !== '' && $code !== '000') $t .= " (HTTP $code)";
      $l[$port] = $t;
    }
    ksort($l);
    $d = implode(' ; ', $l);
    if ($l && strpos(self::ss(), 'users:(') === false) $d .= ' (' . __('processus invisibles sans sudo : seuls les numéros de « Ports acceptés » comptent', __FILE__) . ')';
    return [count($l) > 0, $d];
  }

  // MariaDB sur toutes les interfaces. Debian 12 : mariadb.socket (activation systemd, ListenStream=3306) ouvre le port lui-même → bind-address ignoré
  public static function test_mysql_ecoute() {
    $p = self::ecoutes(self::ss())[3306] ?? null;
    if ($p === null) return [false, ''];
    if (!$p) return [true, __('processus inconnu (sudo nécessaire pour savoir si bind-address suffit)', __FILE__)];
    return [true, in_array('systemd', $p) ? __('port ouvert par systemd (mariadb.socket) : bind-address est ignoré', __FILE__) : __('réglé par bind-address', __FILE__)];
  }

  // Z-Wave JS UI sur toutes les interfaces : problème seulement si son API répond sans authentification (code 3 = refus d'authentification).
  // API muette : réglage gateway.authEnabled du store du plugin zwavejs. ponytail: le mot de passe par défaut n'est pas essayé (ce serait une tentative de connexion)
  public static function test_zwavejs_ui() {
    if (!isset(self::ecoutes(self::ss())[8091])) return [false, ''];
    $r = json_decode((string)shell_exec('curl -sL -m 5 http://127.0.0.1:8091/api/settings 2>/dev/null'), true);
    if (($r['success'] ?? null) === true) return [true, __('l\'API répond sans authentification', __FILE__)];
    $s = json_decode((string)@file_get_contents('/var/www/html/plugins/zwavejs/data/store/settings.json'), true);
    if (($r['code'] ?? null) == 3 || ($s['gateway']['authEnabled'] ?? null) === true)
      return [false, __('authentification activée (mot de passe par défaut « zwave » à changer s\'il ne l\'a pas été)', __FILE__)];
    if (($s['gateway']['authEnabled'] ?? null) === false) return [true, __('authentification désactivée', __FILE__)];
    return [true, __('authentification non vérifiable', __FILE__)];
  }

  // Connexions SSH « Accepted password » du journal : [utilisateur => [IP…]]
  public static function connexionsMdp($j) {
    preg_match_all('/Accepted (?:password|keyboard-interactive\/pam) for (\S+) from (\S+)/', $j, $m, PREG_SET_ORDER);
    $l = [];
    foreach ($m as [, $u, $ip]) $l[$u][$ip] = $ip;
    return array_map(fn($x) => array_values($x), $l);
  }

  // Fichiers authorized_keys précédés de « == chemin » : [compte => nombre de clés] (comptes avec au moins une clé)
  public static function clesSsh($txt) {
    $l = [];
    $u = null;
    foreach (explode("\n", $txt) as $x) {
      if (preg_match('#^== /(?:root|home/([^/]+))/\.ssh/authorized_keys$#', $x, $m)) $u = ($m[1] ?? '') ?: 'root';
      elseif ($u !== null && preg_match('/^\s*[^#\s]/', $x)) $l[$u] = ($l[$u] ?? 0) + 1;
    }
    return $l;
  }

  // Mot de passe accepté par sshd (directement ou par keyboard-interactive/PAM). Détail : clés installées (couper les mots de passe sans clé = plus d'accès SSH) et qui se connecte encore par mot de passe.
  // ponytail: clés lues dans les emplacements standard seulement (pas un AuthorizedKeysFile déplacé)
  public static function test_ssh_password() {
    if (!preg_match('/^(password|kbdinteractive)authentication yes$/m', (string)shell_exec('sudo -n sshd -T 2>/dev/null'))) return [false, ''];
    $k = self::clesSsh((string)shell_exec("sudo -n sh -c 'for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f \"\$f\" ] && echo \"== \$f\" && cat \"\$f\" && echo; done' 2>/dev/null"));
    $d = [$k ? sprintf(__('clés SSH installées : %s (couper les mots de passe ferme les comptes sans clé)', __FILE__), implode(', ', array_map(fn($u, $n) => "$u $n", array_keys($k), $k)))
             : __('aucune clé SSH installée : en installer une avant de couper les mots de passe', __FILE__)];
    // Identifiant sshd plutôt que l'unité (ssh@… d'un ssh.socket) ; date de la plus vieille ligne lue : un journal effacé au redémarrage ne remonte pas à 30 j
    // OpenSSH 9.8+ : les connexions sont journalisées par sshd-session
    // code de sortie 124 = timeout : journal pas lu en entier
    $j = (string)shell_exec("{ timeout 10 sudo -n journalctl -t sshd -t sshd-session --since -30d -q --no-pager -o cat 2>/dev/null; echo \"rc=\$?\"; } | grep -E '^rc=|Accepted '");
    $c = self::connexionsMdp($j);
    $debut = preg_match('/^\d{4}-\d\d-\d\d/', (string)shell_exec('timeout 10 sudo -n journalctl --since -30d -q --no-pager -o short-iso 2>/dev/null | head -n 1'), $m) ? $m[0] : '?';
    $d[] = $c ? sprintf(__('connexions par mot de passe depuis le %s : %s', __FILE__), $debut, implode(' ; ', array_map(fn($u, $ips) => sprintf(__('%s depuis %s', __FILE__), $u, implode(', ', $ips)), array_keys($c), $c)))
              : sprintf(__('aucune connexion par mot de passe depuis le %s', __FILE__), $debut);
    if (preg_match('/^rc=124$/m', $j)) $d[] = __('journal non lu en entier (délai dépassé)', __FILE__);
    return [true, implode(' — ', $d)];
  }

  // Journal api : requêtes journalisées, chacune marquée refusée (« Error code 2 » = clé refusée) ou en erreur (autre code : ni refus, ni requête acceptée)
  // par la ligne d'erreur qui la suit directement. Refus sans requête juste avant (corps à sauts de ligne, ligne inconnue) : entrée orpheline, IP prise
  // sur la ligne de suite « - IP :x » si elle existe. Clé gardée pour l'identifier, jamais affichée. Plugin et IP viennent de la requête : filtrés.
  // ponytail: journal falsifiable (Jeedom y écrit le corps brut : un saut de ligne fabrique des lignes horodatées) ; rattachement par ordre des lignes,
  // deux clients entrelacés à la même seconde peuvent s'échanger un refus
  public static function requetesApi($txt) {
    $l = [];
    $d = '\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]\[\w+\] ';
    $dernier = null; // entrée créée par la dernière ligne horodatée
    $ipSuite = '?';
    foreach (explode("\n", $txt) as $x) {
      // 1er format : IP ajoutée par Jeedom en fin de ligne (.* gourmand = la dernière). 2e : IP au début, .*? = le premier « : » (le JSON qui suit vient du client)
      if (preg_match('/^' . $d . '(\{.*\}) - IP :(\S+)$/', $x, $m) || preg_match('/^' . $d . '.*? : (\S+) => (\{.*\})$/', $x, $m)) {
        [$json, $ip] = $m[2][0] == '{' ? [$m[2], $m[3]] : [$m[3], $m[2]];
        $j = json_decode(html_entity_decode($json, ENT_QUOTES), true);
        $p = is_array($j['params'] ?? null) ? $j['params'] : (is_array($j) ? $j : []);
        $l[] = ['quand' => $m[1], 'plugin' => is_string($p['plugin'] ?? null) && preg_match('/^[\w-]{1,40}$/', $p['plugin']) ? $p['plugin'] : '',
                'ip' => filter_var($ip, FILTER_VALIDATE_IP) ?: '?', 'cle' => is_string($p['apikey'] ?? null) ? $p['apikey'] : '', 'refuse' => false, 'erreur' => false];
        $dernier = array_key_last($l);
      } elseif (preg_match('/^' . $d . 'Error code (-?\d+) :/', $x, $m)) {
        $e = ['quand' => $m[1], 'refuse' => $m[2] === '2', 'erreur' => $m[2] !== '2'];
        if ($dernier !== null) $l[$dernier] = $e + $l[$dernier];
        elseif ($e['refuse']) $l[] = $e + ['plugin' => '', 'ip' => $ipSuite, 'cle' => '', 'orphelin' => true];
        $dernier = null;
        $ipSuite = '?';
      } else {
        // autre ligne horodatée, ou suite d'un corps à sauts de ligne (une ligne de suite prouve que la « requête » d'avant était dans un corps)
        $dernier = null;
        $ipSuite = preg_match('/ - IP :(\S+)$/', $x, $m) ? (filter_var($m[1], FILTER_VALIDATE_IP) ?: '?') : (preg_match('/^' . $d . '/', $x) ? '?' : $ipSuite);
      }
    }
    return $l;
  }

  // Clients en échec : refus consécutifs de chaque plugin + IP depuis sa dernière requête acceptée (un client réparé sort tout de suite ; une requête en erreur
  // ne compte ni pour ni contre), regroupés par IP (changer de nom de plugin à chaque essai ne fait pas passer sous le seuil). Depuis $depuis, tous clients
  // confondus, orphelins compris : 'externes' = refus venus d'adresses publiques (botnet, série terminée par une requête acceptée), 'total' = tous les refus.
  // ponytail: depuis le réseau local, cette dernière ruse n'est comptée que dans 'total'
  public static function clientsRefuses($req, $depuis) {
    $c = [];
    $ext = [];
    $total = 0;
    foreach ($req as $r) {
      if ($r['erreur'] ?? false) continue;
      $k = "$r[plugin]|$r[ip]";
      // orphelin (refus sans requête lisible) : jamais remis à zéro, compté seulement sur la période
      if (empty($r['orphelin'])) $c[$k] = $r['refuse'] ? ['nb' => ($c[$k]['nb'] ?? 0) + 1] + $r : null;
      if (!$r['refuse'] || $r['quand'] < $depuis) continue;
      $total++;
      // 100.64.0.0/10 : adresses partagées (Tailscale, CGNAT), pas Internet
      if (filter_var($r['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false && (ip2long($r['ip']) & 0xFFC00000) !== 0x64400000)
        $ext[$r['ip']] = ($ext[$r['ip']] ?? 0) + 1;
    }
    $g = [];
    foreach (array_filter($c) as $x) {
      $i = $x['ip'];
      $g[$i] = ['ip' => $i, 'nb' => ($g[$i]['nb'] ?? 0) + $x['nb'], 'quand' => max($g[$i]['quand'] ?? '', $x['quand']),
                'clients' => array_merge($g[$i]['clients'] ?? [], [['plugin' => $x['plugin'], 'cle' => $x['cle'], 'nb' => $x['nb']]])];
    }
    return ['clients' => array_values($g), 'externes' => $ext, 'total' => $total];
  }

  // Adresses refusées en boucle (3 refus ou plus) dans les 200 derniers Ko du journal api, avec à qui appartient la clé de chaque client ; plus les refus venus d'Internet en 24 h
  public static function test_api_refus() {
    $f = log::getPathToLog('api');
    $t = is_file($f) ? (string)file_get_contents($f, false, null, max(0, filesize($f) - 200000)) : '';
    $r = self::clientsRefuses(self::requetesApi($t), date('Y-m-d H:i:s', time() - 86400));
    $l = [];
    foreach ($r['clients'] as $g) {
      if ($g['nb'] < 3) continue;
      $qui = [];
      foreach ($g['clients'] as $c) {
        $u = $c['cle'] !== '' ? user::byHash($c['cle']) : null;
        if (is_object($u)) $q = sprintf($u->getEnable() ? __('clé du compte %s', __FILE__) : __('clé du compte désactivé %s', __FILE__), $u->getLogin());
        elseif ($c['cle'] === '') $q = __('sans clé', __FILE__);
        elseif (in_array($c['cle'], [config::byKey('api'), config::byKey('api', $c['plugin'] ?: 'core')], true)) $q = __('clé valide (refusé pour l\'adresse ou les droits)', __FILE__);
        else $q = __('clé inconnue', __FILE__);
        $qui[] = ($c['plugin'] ?: __('client', __FILE__)) . " ($q)";
      }
      $qui = array_unique($qui);
      $l[] = sprintf(__('%s : %s refus, dernier le %s — %s', __FILE__), $g['ip'], $g['nb'], $g['quand'], implode(', ', array_slice($qui, 0, 5)) . (count($qui) > 5 ? ', …' : ''));
    }
    if (($n = array_sum($r['externes'])) >= 10) $l[] = sprintf(__('%s refus depuis Internet en 24 h (%s adresse(s))', __FILE__), $n, count($r['externes']));
    // refus que rien d'autre n'attribue (corps à sauts de ligne, clients entrelacés)
    if (!$l && $r['total'] >= 20) $l[] = sprintf(__('%s refus de clé API en 24 h (attribution par adresse non garantie)', __FILE__), $r['total']);
    // ponytail: état des règles entetes_ip et remoteip lu dans le rapport précédent (l'audit en cours n'est pas encore enregistré ; rien au premier audit)
    if ($l && array_filter(secaudit::rapport()['resultats'] ?? [], fn($x) => in_array($x['id'], ['entetes_ip', 'remoteip']) && $x['etat'] == 'probleme'))
      $l[] = __('adresses falsifiables (en-têtes X-Forwarded-For & co acceptés)', __FILE__);
    return [count($l) > 0, implode(' ; ', $l)];
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
