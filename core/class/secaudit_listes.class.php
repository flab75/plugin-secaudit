<?php
/* Listes blanche et noire du plugin (configuration) : IP ou réseaux CIDR, IPv4 ou IPv6, un par ligne, « # » pour un commentaire.
   Blanche = vos adresses (box, 4G, bureau) : une IP bannie de la liste déclenche toujours l'alerte.
   Noire = jamais « sans doute vous », même depuis une box française, sans limite de largeur. Une IP dans les deux : la noire l'emporte. Les listes ne bannissent ni ne débannissent rien. */
class secaudit_listes {
  // Le réseau $r (IP, IP/n) contient-il $ip ?
  public static function couvre($r, $ip) {
    [$n, $l] = array_pad(explode('/', trim($r), 2), 2, null);
    $a = @inet_pton($n);
    $b = @inet_pton((string)$ip);
    if ($a === false || $b === false || strlen($a) != strlen($b)) return false;
    $l = $l === null ? strlen($a) * 8 : (int)$l;
    if ($l < 0 || $l > strlen($a) * 8) return false;
    $o = intdiv($l, 8);
    $r = $l % 8;
    return substr($a, 0, $o) === substr($b, 0, $o) && ($r == 0 || ord($a[$o]) >> (8 - $r) == ord($b[$o]) >> (8 - $r));
  }

  public static function valide($e) {
    [$n, $l] = array_pad(explode('/', $e, 2), 2, null);
    $v4 = filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    return filter_var($n, FILTER_VALIDATE_IP) && ($l === null || (ctype_digit($l) && $l <= ($v4 ? 32 : 128)));
  }

  // Texte saisi → entrées ; $strict : une entrée illisible est refusée (enregistrement) au lieu d'être ignorée (lecture)
  public static function entrees($texte, $strict = false) {
    $l = [];
    foreach (preg_split('/\R/', (string)$texte) as $x) {
      foreach (preg_split('/[\s,;]+/', trim(explode('#', $x)[0]), -1, PREG_SPLIT_NO_EMPTY) as $e) {
        if (self::valide($e)) $l[] = $e;
        elseif ($strict) throw new Exception(sprintf(__('Adresse illisible dans la liste : %s (attendu : 1.2.3.4, 1.2.3.0/24 ou 2a01:db8::/32)', __FILE__), $e));
      }
    }
    return $l;
  }

  // Plus large qu'un /24 (IPv4) ou un /48 (IPv6, un abonné) : tout un opérateur en liste blanche ferait prendre ses robots pour vous
  public static function tropLarge($e) {
    [$n, $l] = array_pad(explode('/', $e, 2), 2, null);
    return $l !== null && $l < (filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 24 : 48);
  }

  // Liste blanche : une entrée trop large saisie avant la 0.12 est ignorée (affichée sur la page). Liste noire : plus large = plus sûr, pas de limite
  public static function contient($liste, $ip) {
    foreach (self::entrees(config::byKey($liste, 'secaudit', '')) as $r) if (!($liste == 'liste_blanche' && self::tropLarge($r)) && self::couvre($r, $ip)) return true;
    return false;
  }

  public static function ignorees() {
    return array_values(array_filter(self::entrees(config::byKey('liste_blanche', 'secaudit', '')), 'secaudit_listes::tropLarge'));
  }

  public static function blanche($ip) { return self::contient('liste_blanche', $ip); }
  public static function noire($ip) { return self::contient('liste_noire', $ip); }

  // Appelé par config::save (preConfig_*) : refuse une liste illisible, ou (liste blanche) un réseau trop large. Une IP dans les deux listes : la noire l'emporte
  // $avant : valeur enregistrée ; ses entrées ne sont pas revérifiées (saisies avant une règle, ou votre IP 4G du moment : elles bloqueraient tout ajout)
  public static function verifier($texte, $blanche = true, $avant = '') {
    // ponytail: une liste noire plus étroite qu'une entrée blanche, sans son adresse de base (203.0.113.128/25 dans 203.0.113.0/24), passe : la noire l'emporte, voulu
    // liste noire : elle coupe l'alerte « sans doute vous », elle ne doit couvrir ni l'adresse d'où vous enregistrez ni votre liste blanche
    // liste blanche : dans l'autre sens, une entrée couverte par la liste noire enregistrée n'aurait jamais l'alerte
    $base = fn($b) => explode('/', $b)[0];
    $vous = array_filter(array_merge([getClientIp()], array_map($base, array_diff(self::entrees(config::byKey('liste_blanche', 'secaudit', '')), self::ignorees()))));
    $noire = self::entrees(config::byKey('liste_noire', 'secaudit', ''));
    foreach (array_diff(self::entrees($texte, true), self::entrees($avant)) as $e) {
      if ($blanche && self::tropLarge($e)) throw new Exception(sprintf(__('Réseau trop large : %s (au plus /24 en IPv4, /48 en IPv6)', __FILE__), $e));
      if ($blanche) foreach ($noire as $n) if (self::couvre($n, $base($e))) throw new Exception(sprintf(__('%s est couverte par la liste noire (%s) : retirez-la de la liste noire d\'abord', __FILE__), $e, $n));
      if (!$blanche) foreach ($vous as $ip) if (self::couvre($e, $ip)) throw new Exception(sprintf(__('La liste noire %s couvre %s (votre adresse actuelle ou votre liste blanche)', __FILE__), $e, $ip));
    }
    return $texte;
  }
}
