<?php
/* Correctifs (locaux, sur clic) : l'ancienne valeur est gardée dans data/sauvegardes.json. */
class secaudit_correctifs {
  const ARCHIVE = '/var/backups/jeedom_web_data';

  public static function corriger($id) {
    $c = array_column(secaudit_regles::lireJson(secaudit_regles::LOCALES)['checks'], null, 'id')[$id] ?? null; // jamais depuis la base distante
    $m = 'fix_' . ($c['fix'] ?? '');
    if (!$c || !method_exists(__CLASS__, $m)) throw new Exception(sprintf(__('Pas de correctif pour %s', __FILE__), $id));
    $detail = self::$m($c);
    log::add('secaudit', 'info', "Correctif $id : $detail");
    secaudit::run();
    return $detail;
  }

  private static function fichiersRestants($f) {
    clearstatcache();
    return array_values(array_filter($f, 'file_exists'));
  }

  private static function sauvegarder($quoi, $valeur) {
    // ponytail: dans le dossier du plugin, effacé par une réinstallation ; le log secaudit garde aussi chaque ancienne valeur
    log::add('secaudit', 'info', "Sauvegarde $quoi avant correctif : " . json_encode($valeur, JSON_UNESCAPED_UNICODE));
    $fp = fopen(__DIR__ . '/../../data/sauvegardes.json', 'c+');
    flock($fp, LOCK_EX);
    $j = json_decode(stream_get_contents($fp), true);
    $j = is_array($j) ? $j : [];
    $j[] = ['date' => date('Y-m-d H:i:s'), 'quoi' => $quoi, 'avant' => $valeur];
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
    fclose($fp);
  }

  // Seulement l'API de la règle cliquée (l'avertissement affiché ne parlait que d'elle)
  private static function fix_api_whiteip($c) {
    $k = $c['key'];
    // sans 127.0.0.1 en liste blanche, les plugins locaux (Homebridge…) perdraient l'API
    // entrée qui couvre 127.0.0.1 (127.0.0.1, 127.0.0.0/8, 127.*.*.*), avec la fonction de Jeedom qui lit cette liste (IPv6 et entrées illisibles sautées : netMatch peut lever une erreur)
    if (!array_filter(explode(';', (string)config::byKey('security::whiteips')), fn($e) => trim($e) !== '' && strpos($e, ':') === false && !secaudit_tests::large($e) && netMatch(trim($e), '127.0.0.1')))
      throw new Exception(__('Ajoutez d\'abord 127.0.0.1 à la liste blanche (Réglages › Système › Configuration › Réseaux)', __FILE__));
    if (config::byKey($k) != 'enable') return "$k n'est plus « enable », rien à faire";
    self::sauvegarder($k, 'enable');
    config::save($k, 'whiteip');
    return "$k passé en IP blanche";
  }

  // Retire de la liste blanche les entrées trop larges (même test que la règle whiteips_large), garde les autres, ajoute le réseau local
  private static function fix_whiteips($c) {
    $ip = network::getNetworkAccess('internal', 'ip');
    if (!preg_match('/^(\d+\.\d+\.\d+)\.\d+$/', $ip, $m)) throw new Exception(sprintf(__('adresse interne illisible : %s', __FILE__), $ip));
    $avant = (string)config::byKey('security::whiteips');
    self::sauvegarder('security::whiteips', $avant);
    $l = array_filter(array_map('trim', explode(';', $avant)), fn($x) => $x !== '' && !secaudit_tests::large($x));
    $v = implode(';', array_unique(array_merge(['127.0.0.1', $m[1] . '.*'], $l)));
    config::save('security::whiteips', $v);
    return "liste blanche = $v (avant : $avant)";
  }

  private static function fix_fichiers_publics($c) {
    $f = secaudit_tests::fichiersPublics();
    if (!$f) return 'rien à déplacer';
    $dest = self::ARCHIVE . '/' . date('Ymd_His');
    $r = trim((string)shell_exec('sudo -n mkdir -p ' . escapeshellarg($dest) . ' && sudo -n mv ' . implode(' ', array_map('escapeshellarg', $f)) . ' ' . escapeshellarg($dest) . ' 2>&1'));
    $reste = self::fichiersRestants($f);
    $faits = array_diff($f, $reste);
    if ($faits) self::sauvegarder('fichiers_publics', array_map('basename', $faits));
    if ($reste) throw new Exception(sprintf(__('%s déplacé(s), %s non déplacé(s) (%s) : %s', __FILE__), count($faits), count($reste), implode(', ', array_map('basename', $reste)), $r));
    return count($f) . " fichier(s) déplacé(s) vers $dest";
  }
}
