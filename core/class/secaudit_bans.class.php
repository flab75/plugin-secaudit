<?php
/* Bannissements : lecture (fail2ban, toutes prisons, + Jeedom), journal fail2ban, IP jamais bannies, débannissement. */
class secaudit_bans {
  // Ligne de `fail2ban-client get <prison> banip --with-time` : « ip  début + durée = fin »
  public static function lireBanip($l) {
    return preg_match('/^(\S+)\s+(\S+ \S+) \+ -?\d+ = (\S+ \S+)/', trim($l), $m) ? ['ip' => $m[1], 'debut' => $m[2], 'fin' => $m[3]] : null;
  }

  public static function prisons() {
    $st = (string)shell_exec('sudo -n fail2ban-client status 2>/dev/null');
    return preg_match('/Jail list:\s*(.*)/', $st, $m) ? preg_split('/[,\s]+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY) : [];
  }

  private static function bansJeedom() {
    $c = cache::byKey('security::banip')->getValue('[]');
    $c = is_array($c) ? $c : json_decode($c, true);
    return is_array($c) ? array_values($c) : [];
  }

  // IP bannies : ip => [[source, prison, fin], …] ; $fail2ban = false : Jeedom seul (cron5, sans sudo)
  public static function liste($fail2ban = true) {
    $l = [];
    foreach ($fail2ban ? self::prisons() : [] as $j)
      foreach (explode("\n", (string)shell_exec('sudo -n fail2ban-client get ' . escapeshellarg($j) . ' banip --with-time 2>/dev/null')) as $x)
        if ($b = self::lireBanip($x)) $l[$b['ip']][] = ['source' => 'fail2ban', 'prison' => $j, 'fin' => $b['fin']];
    $duree = (int)config::byKey('security::bantime');
    foreach (self::bansJeedom() as $b)
      // Jeedom ne purge ses bans expirés qu'à la prochaine connexion : on ne garde que les actifs
      if (isset($b['ip'], $b['datetime']) && ($duree < 0 || $b['datetime'] + $duree > time())) $l[$b['ip']][] = ['source' => 'jeedom', 'prison' => '', 'fin' => $duree < 0 ? __('jamais', __FILE__) : date('Y-m-d H:i:s', $b['datetime'] + $duree)];
    return $l;
  }

  // Bans vus ces 30 dernières heures, même levés depuis (un ban Jeedom dure 10 min : levé avant le cron horaire qui calcule l'alerte).
  // 30 h et pas 24 : le rapport de 8 h tourne avec le cron horaire et peut lire l'alerte de 7 h ; un ban de 7 h 10 sort alors le lendemain.
  // Relevé toutes les 5 min (cron5, bans Jeedom) et à chaque analyse (tous) : ip => [prison fail2ban ou « jeedom » => vu la première fois le].
  // Première vue : un ban de 8 h relu chaque heure resterait sinon ~38 h dans la fenêtre (alerte le surlendemain, sans bouton Débannir)
  // ponytail: config lue puis réécrite sans verrou (cron5 et page) → au pire un relevé perdu, rattrapé 5 min plus tard
  const VUS = 30 * 3600;
  // Gardé au-delà de 30 h tant que le ban est actif (bantime long ou -1) : sinon purgé puis revu avec une nouvelle date.
  // $fail2ban = false (cron5, Jeedom seul, ou fail2ban muet) : les bans fail2ban n'y sont pas, on ne purge les leurs qu'après 7 jours
  public static function memoriser($bans, $fail2ban = true) {
    $r = config::byKey('bans_vus', 'secaudit', []);
    $r = is_array($r) ? $r : [];
    foreach ($bans as $ip => $l) foreach ($l as $b) $r[$ip][$b['prison'] ?: $b['source']] ??= time();
    foreach ($r as $ip => $s) {
      $actifs = array_map(fn($b) => $b['prison'] ?: $b['source'], $bans[$ip] ?? []);
      $s = array_filter($s, fn($t, $k) => $t > time() - self::VUS || in_array($k, $actifs, true) || (!$fail2ban && $k != 'jeedom' && $t > time() - 7 * 86400), ARRAY_FILTER_USE_BOTH);
      if ($s) $r[$ip] = $s; else unset($r[$ip]);
    }
    config::save('bans_vus', $r, 'secaudit');
    return $r;
  }

  // 20 derniers bannissements / levées
  public static function journal() {
    return array_slice(explode("\n", trim((string)shell_exec('sudo -n grep -E " (Ban|Unban) " /var/log/fail2ban.log 2>/dev/null'))), -20);
  }

  // IP / réseaux jamais bannis (ignoreip, lu sur la première prison) : lignes « |- 127.0.0.1/8 » et « `- ::1 »
  public static function lireIgnoreip($sortie) {
    return preg_match_all('/^\s*[|`]-\s*(\S+)/m', $sortie, $m) ? implode(' ', $m[1]) : '';
  }

  public static function ignorees() {
    $p = self::prisons()[0] ?? '';
    return $p ? self::lireIgnoreip((string)shell_exec('sudo -n fail2ban-client get ' . escapeshellarg($p) . ' ignoreip 2>/dev/null')) : '';
  }

  public static function debannir($source, $prison, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new Exception(sprintf(__('IP invalide : %s', __FILE__), $ip));
    if ($source == 'fail2ban') {
      $p = self::prisons();
      $vu = isset(config::byKey('bans_vus', 'secaudit', [])[$ip][$prison]);
      if (!$p && $vu) $r = 'alerte effacée (fail2ban ne répond pas)'; // sinon l'alerte resterait jusqu'à 7 jours sans bouton qui marche
      elseif (!in_array($prison, $p, true)) throw new Exception(sprintf(__('Prison inconnue : %s', __FILE__), $prison));
      else $r = trim((string)shell_exec('sudo -n fail2ban-client set ' . escapeshellarg($prison) . ' unbanip ' . escapeshellarg($ip) . ' 2>&1'));
      // répond le nombre d'IP levées (0 si déjà levée), en dernière ligne : sudo peut écrire un avertissement avant
      if ($p && !ctype_digit(trim(strrchr("\n$r", "\n")))) {
        log::add('secaudit', 'error', "Débannissement $ip ($prison) refusé par fail2ban : $r");
        throw new Exception(sprintf(__('fail2ban n\'a pas débanni %s : %s', __FILE__), $ip, $r));
      }
    } elseif ($source == 'jeedom') {
      cache::set('security::banip', json_encode(array_values(array_filter(self::bansJeedom(), function ($b) use ($ip) { return ($b['ip'] ?? '') != $ip; }))));
      cache::delete('security::failed_login::' . $ip); // sinon un seul nouvel échec rebannit aussitôt
      $r = 'ok';
    } else throw new Exception(sprintf(__('Source inconnue : %s', __FILE__), $source));
    $v = config::byKey('bans_vus', 'secaudit', []); // sinon l'alerte « ban déjà levé » revient jusqu'à 30 h
    $k = $source == 'jeedom' ? 'jeedom' : $prison;
    if (is_array($v) && isset($v[$ip][$k])) {
      unset($v[$ip][$k]);
      if (!$v[$ip]) unset($v[$ip]);
      config::save('bans_vus', $v, 'secaudit');
    }
    log::add('secaudit', 'info', "Débannissement $ip ($source $prison) : $r");
    secaudit::majTentatives(); // sinon le rapport de 8 h peut lire l'alerte de 7 h qui nomme encore cette IP
    return $r;
  }
}
