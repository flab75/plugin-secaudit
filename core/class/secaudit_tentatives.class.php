<?php
/* Croisement : historique des essais par IP × bannissements × whois (cache) → données de la page et du rapport. */
class secaudit_tentatives {
  const WHOIS_PAR_HEURE = 6; // 10 s au pire chacun : le cron horaire des autres plugins attend derrière

  public static function analyser() {
    $bans = secaudit_bans::liste();      // actifs : affichage et bouton Débannir
    $recents = secaudit_bans::memoriser($bans, (bool)secaudit_bans::prisons()); // vus depuis 30 h, même levés : alerte. fail2ban muet : ses bans ne sont pas purgés
    $h = secaudit_historique::enregistrer();
    foreach (array_keys($bans + $recents) as $ip) $h[$ip] = $h[$ip] ?? ['nb' => 0, 'premier' => 0, 'dernier' => 0, 'chemins' => [], 'familles' => []];

    $lignes = [];
    $nonClasses = [];
    $depuis = null;
    foreach ($h as $ip => $x) {
      $ip = (string)$ip;
      foreach ($x['chemins'] as $c) if (secaudit_journal::famille($c) == 'autre') $nonClasses[$c] = 1;
      $fam = $x['familles'] ?? []; // comptées sur tous les essais, pas seulement les 20 chemins gardés en exemple
      arsort($fam);
      if ($x['premier']) $depuis = min($depuis ?? $x['premier'], $x['premier']);
      $lignes[] = ['ip' => $ip, 'nb' => $x['nb'], 'dernier' => $x['dernier'] ? date('Y-m-d H:i', $x['dernier']) : '',
                   'qui' => secaudit_whois::proprietaire($ip), 'familles' => array_keys($fam),
                   // seulement des scripts Jeedom absents : un navigateur ou une appli à vous, pas un robot
                   'jeedom_seul' => array_keys($fam) == ['jeedom'],
                   'exemples' => array_slice($x['chemins'], 0, 4), 'bans' => $bans[$ip] ?? [],
                   'bans_recents' => array_keys($recents[$ip] ?? []), 'vu' => max($recents[$ip] ?? [0]),
                   'liste' => secaudit_listes::noire($ip) ? 'noire' : (secaudit_listes::blanche($ip) ? 'blanche' : '')];
    }
    usort($lignes, fn($a, $b) => [!$a['bans_recents'], -$a['nb']] <=> [!$b['bans_recents'], -$b['nb']]);
    return [
      'lignes' => $lignes,
      'depuis' => $depuis ? date('Y-m-d H:i', $depuis) : '',
      'resume' => secaudit_resume::texte($lignes, $depuis),
      'alerte' => secaudit_resume::alerte($lignes),
      'non_classes' => array_slice(array_keys($nonClasses), 0, 15),
      'journal' => secaudit_bans::journal(),
      'ignore' => secaudit_bans::ignorees(),
      'mon_ip' => getClientIp(),
    ];
  }

  // Cron horaire : whois des IP bannies (30 h) ou insistantes (≥ 3 essais) pas encore identifiées, 6 au plus par passage.
  // Bannies par Jeedom d'abord : leur pays décide de l'alerte, alors qu'elles n'ont souvent aucun essai et passeraient après les robots sshd.
  // Sautées : listes blanche et noire, bans sshd / recidive seuls sans essai (le whois n'y change pas l'alerte, il prendrait les places)
  public static function identifier() {
    $n = 0;
    $l = array_filter(self::analyser()['lignes'], fn($x) => !$x['liste'] && ($x['nb'] || array_diff($x['bans_recents'], ['sshd', 'recidive'])));
    usort($l, fn($a, $b) => !in_array('jeedom', $a['bans_recents'], true) <=> !in_array('jeedom', $b['bans_recents'], true));
    foreach ($l as $x) {
      if ($n >= self::WHOIS_PAR_HEURE) break;
      if (($x['bans_recents'] || $x['nb'] >= 3) && secaudit_whois::aIdentifier($x['ip'])) {
        secaudit_whois::identifier($x['ip']);
        $n++;
      }
    }
    return $n;
  }
}
