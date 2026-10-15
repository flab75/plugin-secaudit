<?php
/* Résumé en langage courant (langue de Jeedom) des tentatives (page et rapport du matin), et alerte quand c'est probablement vous qui êtes banni. */
class secaudit_resume {
  public static function texte($lignes, $depuis) {
    // nb = 0 : bannie (sshd, mots de passe Jeedom…) sans essai dans http.error, elle n'a pas « sondé » les pages
    // une IP de la liste blanche qui a cherché autre chose que Jeedom (.env, webshell…) reste comptée avec les robots
    $vous = fn($x) => self::estVous($x) && !array_diff($x['familles'], ['jeedom']);
    $ext = array_filter($lignes, fn($x) => $x['qui']['profil'] != 'chez vous' && !$vous($x) && $x['nb']);
    $appli = array_filter($lignes, fn($x) => $x['qui']['profil'] != 'chez vous' && $vous($x) && $x['nb']);
    $chez = array_filter($lignes, fn($x) => $x['qui']['profil'] == 'chez vous' && $x['nb']);
    if (!$ext && !$appli && !$chez) return __('Aucune tentative suspecte dans le journal.', __FILE__);
    $obj = [];
    foreach ($ext as $x) foreach ($x['familles'] as $f) $obj[$f] = ($obj[$f] ?? 0) + 1;
    arsort($obj);
    $t = [];
    if ($ext) {
      // phrases entières (%1$s nombre, %2$s date, %3$s bannies, %4$s objectifs) : l'anglais a son propre ordre
      $t[] = sprintf($depuis ? __('%1$s adresse(s) extérieure(s) ont sondé Jeedom depuis le %2$s, dont %3$s bannie(s). Ce qu\'elles cherchaient : %4$s.', __FILE__)
        : __('%1$s adresse(s) extérieure(s) ont sondé Jeedom, dont %3$s bannie(s). Ce qu\'elles cherchaient : %4$s.', __FILE__),
        count($ext), $depuis ? date('d/m H:i', $depuis) : '', count(array_filter($ext, fn($x) => $x['bans'])),
        implode(' ; ', array_map(fn($f, $n) => secaudit_journal::texte($f) . " ($n)", array_keys($obj), $obj)));
      // Le journal ne garde que les refus et les scripts absents : une tentative réussie n'y serait pas (cf. règle chemins_vises)
      $t[] = __('Les essais visibles dans le journal ont été refusés par Apache ou visaient des fichiers absents.', __FILE__);
    }
    if ($appli) $t[] = sprintf(__('%s adresse(s) extérieure(s) de votre liste blanche ou n\'ayant demandé que des scripts Jeedom absents (%s) : sans doute vous en déplacement ou une de vos applis.', __FILE__),
      count($appli), implode(', ', array_column($appli, 'ip')));
    if ($chez) $t[] = sprintf(__('Erreurs venant de chez vous (%s) : sans danger, mais c\'est ce qui peut provoquer un bannissement.', __FILE__), implode(', ', array_column($chez, 'ip')));
    return implode("\n", $t);
  }

  // Probablement vous : liste blanche, réseau local, ou connexion de particulier française qui n'a demandé que des scripts Jeedom
  // ou que Jeedom a bannie (mots de passe ratés) sans aucun essai suspect. Jamais la liste noire, un hébergeur, un scanner, un VPN,
  // un propriétaire non reconnu ou pas encore identifié : l'alerte propose de débannir, elle ne doit pas le proposer pour un robot.
  // ponytail: un robot sur une box française qui ne tente que des mots de passe passerait pour vous (rare) → liste noire ;
  // vous depuis l'étranger, un VPN ou un opérateur non reconnu → liste blanche
  public static function estVous($x) {
    if (($x['liste'] ?? '') == 'noire') return false;
    $p = $x['qui']['profil'];
    if ($p == 'chez vous' || ($x['liste'] ?? '') == 'blanche') return true;
    if (strpos($p, 'particulier') === false || ($x['qui']['pays'] ?? '') != 'FR') return false;
    return $x['jeedom_seul'] || (!$x['familles'] && in_array('jeedom', $x['bans_recents'], true));
  }

  // Seul cas à signaler chaque matin : une IP bannie qui est probablement vous (sinon = bruit de fond normal des robots).
  // Un ban sshd / recidive seul ne compte que pour la liste blanche : votre téléphone ne fait pas de SSH, les robots si.
  // Daté : un ban vu à 7 h 10 est encore dans les 30 h le lendemain à 8 h
  public static function alerte($lignes) {
    $l = array_filter($lignes, fn($x) => $x['bans_recents'] && self::estVous($x)
      && (array_diff($x['bans_recents'], ['sshd', 'recidive']) || ($x['liste'] ?? '') == 'blanche'));
    // une phrase entière par cas (ban encore actif ou levé, autres recherches ou non) : %1$s IP, %2$s jour, %3$s heure, %4$s objectifs
    $p = [__('%1$s (vue bannie le %2$s à %3$s)', __FILE__), __('%1$s (vue bannie le %2$s à %3$s, ban déjà levé)', __FILE__),
      __('%1$s (vue bannie le %2$s à %3$s ; attention, a aussi cherché : %4$s, vérifier avant de débannir)', __FILE__),
      __('%1$s (vue bannie le %2$s à %3$s, ban déjà levé ; attention, a aussi cherché : %4$s, vérifier avant de débannir)', __FILE__)];
    return $l ? sprintf(__('IP bannie depuis hier matin qui est sans doute vous ou une de vos applis : %s — bouton Débannir (ou Effacer l\'alerte si le ban est levé) sur la page du plugin.', __FILE__),
      implode(', ', array_map(function ($x) use ($p) {
        $f = array_diff($x['familles'], ['jeedom']);
        $t = $x['vu'] ?? time();
        return sprintf($p[($x['bans'] ? 0 : 1) + ($f ? 2 : 0)], $x['ip'], date('d/m', $t), date('H:i', $t), implode(', ', array_map('secaudit_journal::texte', $f)));
      }, $l))) : '';
  }
}
