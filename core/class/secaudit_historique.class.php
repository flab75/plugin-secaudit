<?php
/* Historique des essais par IP (data/historique.json, 30 jours, 500 IP) : Jeedom ramène http.error à quelques centaines de lignes,
   on le relit donc souvent (cron horaire + affichage de la page) en ne comptant que les lignes plus récentes que le dernier passage.
   Fichier sous verrou : la page et les crons (horaire et quotidien tournent ensemble à minuit) l'écrivent sans se marcher dessus. */
class secaudit_historique {
  const FICHIER = __DIR__ . '/../../data/historique.json';
  const JOURS = 30;
  const MAX_IP = 500;
  const MAX_CHEMINS = 20;   // exemples seulement : les familles, elles, sont comptées sur tous les essais
  const LONGUEUR = 200;     // un chemin choisi par l'attaquant peut faire des Ko

  private static function decoder($t) {
    $d = json_decode((string)$t, true);
    return is_array($d['ip'] ?? null) ? $d : ['vu' => 0, 'ip' => []];
  }

  public static function lire() {
    return self::decoder(@file_get_contents(self::FICHIER))['ip'];
  }

  // Ajoute les essais au-delà du repère « vu » ; renvoie l'historique à jour (ip => nb, premier, dernier, chemins, familles)
  // ponytail: repère à la seconde → une ligne écrite dans la même seconde qu'un passage peut être perdue (sans importance pour des statistiques)
  public static function enregistrer() {
    $fp = @fopen(self::FICHIER, 'c+');
    if (!$fp) return self::lire();
    flock($fp, LOCK_EX);
    $d = self::decoder(stream_get_contents($fp));
    $h = $d['ip'];
    $max = $d['vu'];
    foreach (secaudit_journal::essais() as $e) {
      if ($e['t'] <= $d['vu']) continue;
      $max = max($max, $e['t']);
      $x = $h[$e['ip']] ?? ['nb' => 0, 'premier' => $e['t'], 'dernier' => 0, 'chemins' => [], 'familles' => []];
      $x['nb']++;
      $x['dernier'] = max($x['dernier'], $e['t']);
      $f = secaudit_journal::famille($e['chemin']);
      $x['familles'][$f] = ($x['familles'][$f] ?? 0) + 1;
      $c = mb_substr($e['chemin'], 0, self::LONGUEUR);
      if (!in_array($c, $x['chemins'], true) && count($x['chemins']) < self::MAX_CHEMINS) $x['chemins'][] = $c;
      $h[$e['ip']] = $x;
    }
    if ($max > $d['vu']) {
      $h = array_filter($h, fn($x) => $x['dernier'] > time() - self::JOURS * 86400);
      uasort($h, fn($a, $b) => $b['dernier'] <=> $a['dernier']);
      $h = array_slice($h, 0, self::MAX_IP, true);
      $j = json_encode(['vu' => $max, 'ip' => $h], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
      if ($j !== false) { // sinon on garderait un fichier vide : historique perdu et journal recompté
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $j);
        fflush($fp);
      }
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $h;
  }
}
