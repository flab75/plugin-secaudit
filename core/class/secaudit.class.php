<?php
/* Audit de sécurité Jeedom : équipement, lancement de l'audit, rapport. Chaque tâche est dans son module secaudit_*.class.php :
   regles (lire/évaluer les règles), tests (tests intégrés), base (failles connues), correctifs, bans (fail2ban + Jeedom),
   journal (lecture de http.error), historique (essais par IP sur 30 jours), whois (qui est derrière une IP),
   tentatives (croisement), resume (texte et alerte), apprentissage (chemins visés), listes (blanche et noire de la configuration),
   doc (docs/fr_FR/methodes.md dans la page). */
require_once __DIR__ . '/../../../../core/php/core.inc.php';
foreach (glob(__DIR__ . '/secaudit_*.class.php') as $f) require_once $f;

class secaudit extends eqLogic {
  const ORDRE = ['critique' => 0, 'haute' => 1, 'moyenne' => 2, 'info' => 3];

  public static function run() {
    secaudit_apprentissage::apprendre();
    $res = [];
    foreach (secaudit_regles::checks() as $c) {
      try {
        [$pb, $detail] = secaudit_regles::evaluer($c);
        $etat = $pb ? 'probleme' : 'ok';
      } catch (Throwable $e) {
        $etat = 'erreur';
        $detail = $e->getMessage();
      }
      // textes des règles traduits ici (section data/checks.json de core/i18n) : rapport, widget et message dans la langue de Jeedom
      $tr = fn($k) => isset($c[$k]) && $c[$k] !== '' ? __($c[$k], 'plugins/secaudit/data/checks.json') : '';
      $res[] = ['id' => $c['id'], 'titre' => $tr('titre'), 'gravite' => $c['gravite'], 'etat' => $etat, 'detail' => $detail,
                'resolution' => $tr('resolution'), 'reference' => $c['reference'] ?? '', 'fix' => $c['fix'] ?? '', 'avertissement' => $tr('avertissement')];
    }
    usort($res, fn($a, $b) => [$a['etat'] != 'probleme', self::ORDRE[$a['gravite']]] <=> [$b['etat'] != 'probleme', self::ORDRE[$b['gravite']]]);
    $pbs = array_filter($res, fn($r) => $r['etat'] == 'probleme');
    $score = max(0, 100 - array_sum(array_map(fn($r) => secaudit_regles::POIDS[$r['gravite']], $pbs)));

    $avant = array_column(array_filter(self::rapport()['resultats'] ?? [], fn($r) => $r['etat'] == 'probleme'), 'id');
    foreach ($pbs as $r) {
      if (!in_array($r['id'], $avant) && self::ORDRE[$r['gravite']] <= 1) message::add('secaudit', sprintf(__('Audit sécurité : %s', __FILE__), $r['titre']), '', 'secaudit_' . $r['id']);
    }
    $rapport = ['date' => date('Y-m-d H:i:s'), 'score' => $score, 'base' => secaudit_regles::lireJson(secaudit_regles::DISTANTES)['date'] ?? '', 'resultats' => $res];
    config::save('rapport', $rapport, 'secaudit'); // Jeedom encode et décode le JSON lui-même
    $rapport += self::majTentatives();
    log::add('secaudit', 'info', "Audit : score $score, " . count($pbs) . ' problème(s)');

    $resume = implode("\n", array_map(fn($r) => '[' . __($r['gravite'], __FILE__) . '] ' . $r['titre'], array_filter($pbs, fn($r) => $r['gravite'] != 'info')));
    foreach (self::byType('secaudit') as $eq) {
      $eq->checkAndUpdateCmd('score', $score);
      $eq->checkAndUpdateCmd('problemes', count(array_filter($pbs, fn($r) => $r['gravite'] != 'info')));
      $eq->checkAndUpdateCmd('resume', $resume ?: __('Aucun problème', __FILE__));
      $eq->checkAndUpdateCmd('graves', implode(' · ', array_column(array_filter($pbs, fn($r) => self::ORDRE[$r['gravite']] <= 1), 'titre')) ?: __('Aucun problème grave', __FILE__));
    }
    return $rapport;
  }

  // Rapport de l'audit + résumé et alerte des tentatives (clé à part, recalculée chaque heure : le 257 lit l'alerte à 8 h)
  public static function rapport() {
    $r = config::byKey('rapport', 'secaudit', []);
    $t = config::byKey('tentatives', 'secaudit', []);
    return is_array($r) && $r ? array_merge($r, is_array($t) ? $t : []) : [];
  }

  public static function majTentatives() {
    try {
      $t = secaudit_tentatives::analyser();
      $v = ['tentatives' => $t['resume'], 'alerte_tentatives' => $t['alerte']];
    } catch (Throwable $e) {
      $v = ['tentatives' => '', 'alerte_tentatives' => sprintf(__('Analyse des tentatives en erreur : %s', __FILE__), $e->getMessage())];
    }
    config::save('tentatives', $v, 'secaudit');
    return $v;
  }

  // Bans Jeedom (10 min) levés avant le cron horaire : on les note toutes les 5 min pour que l'alerte du matin les voie.
  // fail2ban non relu ici (sudo toutes les 5 min dans auth.log) : ses bans durent des heures, le cron horaire les voit
  // config::save appelle preConfig_<clé> : une liste illisible est refusée avec un message au lieu d'être ignorée en silence
  // seules les entrées ajoutées sont vérifiées : config::save l'appelle à chaque enregistrement de la page
  public static function preConfig_liste_blanche($v) { return secaudit_listes::verifier($v, true, config::byKey('liste_blanche', 'secaudit', '')); }
  public static function preConfig_liste_noire($v) { return secaudit_listes::verifier($v, false, config::byKey('liste_noire', 'secaudit', '')); }

  // Objet choisi dans la configuration : le widget de l'équipement y est affiché ; vide ou objet supprimé = masqué.
  // config::save l'appelle à chaque enregistrement de la page : l'équipement n'est touché que si le choix change (un placement fait à la main reste)
  public static function preConfig_widget_objet($v) {
    $v = (string)$v;
    if ($v !== '' && !is_object(jeeObject::byId($v))) $v = '';
    if ($v === (string)config::byKey('widget_objet', 'secaudit', '') && self::byType('secaudit')) return $v; // équipement supprimé à la main : recréé
    $eq = self::creerEquipement();
    $eq->setObject_id($v === '' ? null : $v);
    $eq->setIsVisible($v === '' ? 0 : 1);
    $eq->save();
    return $v;
  }

  // Assistant de la page (première visite après l'installation, ou la mise à jour vers la 0.19 : clé « assistant » absente) : réponses → configuration ; null = « Plus tard », rien ne change.
  // Liste blanche d'abord : refusée (preConfig) = exception avant d'avoir enregistré le reste
  public static function assistant($r) {
    if ($r !== null) {
      config::save('liste_blanche', (string)($r['liste_blanche'] ?? ''), 'secaudit');
      config::save('widget_objet', (string)($r['widget_objet'] ?? ''), 'secaudit');
      $ok = array_map('trim', explode(',', config::byKey('ports_ok', 'secaudit', '22,80,443,1883,8883,3306,8091')));
      $ok = array_merge($ok, array_filter(explode(',', (string)($r['ports'] ?? '')), 'ctype_digit'));
      config::save('ports_ok', implode(',', array_unique(array_filter($ok, 'strlen'))), 'secaudit');
      config::save('box_ok', ($r['box_ok'] ?? 0) == 1 ? 1 : 0, 'secaudit');
    }
    config::save('assistant', 1, 'secaudit');
    if (($r['lancer'] ?? 0) == 1) self::run();
    return 'ok';
  }

  public static function cron5() {
    secaudit_bans::memoriser(secaudit_bans::liste(false), false);
  }

  public static function cronHourly() {
    // http.error est ramené à quelques centaines de lignes : on retient essais (via analyser) et chemins visés au fil de l'eau
    // une erreur ici ne doit pas empêcher le recalcul de l'alerte (le 257 lirait celle de l'heure d'avant)
    try { secaudit_apprentissage::apprendre(); } catch (Throwable $e) { log::add('secaudit', 'warning', 'Apprentissage : ' . $e->getMessage()); }
    try { secaudit_tentatives::identifier(); } catch (Throwable $e) { log::add('secaudit', 'warning', 'Whois : ' . $e->getMessage()); } // whois ici, pas à l'affichage de la page
    self::majTentatives();
  }

  public static function cronDaily() {
    try { secaudit_base::mettreAJour(); } catch (Throwable $e) { log::add('secaudit', 'warning', 'Base non mise à jour : ' . $e->getMessage()); }
    self::run();
  }

  public static function creerEquipement() {
    $eq = self::byType('secaudit')[0] ?? null;
    if (!$eq) {
      $eq = new self();
      $eq->setName('Audit sécurité');
      $eq->setEqType_name('secaudit');
      $eq->setIsEnable(1);
      $eq->setIsVisible(0);
      $eq->save();
    }
    foreach ([['score', 'Score', 'info', 'numeric', '%'], ['problemes', 'Problèmes', 'info', 'numeric', ''],
              ['resume', 'Résumé', 'info', 'string', ''],
              ['graves', 'Problèmes graves', 'info', 'string', ''], ['lancer', 'Lancer l\'audit', 'action', 'other', '']] as [$id, $nom, $type, $sub, $u]) {
      $cmd = $eq->getCmd(null, $id);
      if (is_object($cmd)) continue;
      $cmd = new secauditCmd();
      $cmd->setLogicalId($id);
      $cmd->setName($nom);
      $cmd->setType($type);
      $cmd->setSubType($sub);
      $cmd->setUnite($u);
      $cmd->setIsVisible((int)in_array($id, ['graves', 'score', 'lancer'])); // widget : problèmes critiques et hauts, score, bouton
      $cmd->setEqLogic_id($eq->getId());
      $cmd->save();
    }
    return $eq;
  }

  // Widget du dashboard : bouton vers la page de l'audit (réservée aux admins), avant le script du template eqLogic
  public function toHtml($_version = 'dashboard') {
    $h = parent::toHtml($_version);
    $p = strrpos($h, '<script>');
    if ($_version != 'dashboard' || $p === false) return $h; // pas les designs (dview, dplan : même rendu que le dashboard)
    return substr_replace($h, '<div class="text-center" style="margin:4px"><a class="btn btn-xs btn-default" href="index.php?v=d&amp;m=secaudit&amp;p=secaudit"><i class="fas fa-shield-alt"></i> ' . __('Voir l\'audit', __FILE__) . '</a></div>', $p, 0);
  }
}

class secauditCmd extends cmd {
  public function execute($_options = []) {
    // un compte non admin ne lance pas l'audit (shell, sudo, ~1 min) : session web, ou utilisateur de l'API (clé utilisateur) ; aucun des deux = scénario ou cron
    global $_USER_GLOBAL;
    $u = is_object($_USER_GLOBAL ?? null) ? $_USER_GLOBAL : ($_SESSION['user'] ?? null);
    if (is_object($u) && $u->getProfils() != 'admin') throw new Exception('{{Réservé aux administrateurs}}');
    if ($this->getLogicalId() == 'lancer') secaudit::run();
  }
}
