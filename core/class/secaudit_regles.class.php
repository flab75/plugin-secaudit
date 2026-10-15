<?php
/* Règles : data/checks.json (locales) + data/checks_remote.json (téléchargées, filtrées), et évaluation d'une règle. */
class secaudit_regles {
  const LOCALES = __DIR__ . '/../../data/checks.json';
  const DISTANTES = __DIR__ . '/../../data/checks_remote.json';
  const POIDS = ['critique' => 25, 'haute' => 10, 'moyenne' => 4, 'info' => 0];
  // Champs texte d'une règle distante et opérateurs des règles « config » (types ajoutables : voir complete()).
  // ponytail: une base distante ne peut jamais apporter de commande shell ni de correctif (sinon = exécution de code à distance),
  // ni réécrire le texte d'une règle locale (une « résolution » piégée serait suivie à la lettre) : elle peut seulement l'aggraver
  const DISTANT_CHAMPS = ['titre', 'gravite', 'resolution', 'reference'];
  const OPS = ['eq', 'neq', 'gt', 'lt', 'empty', 'regex'];

  public static function lireJson($f) {
    $j = is_file($f) ? json_decode(file_get_contents($f), true) : null;
    return is_array($j) && is_array($j['checks'] ?? null) ? $j : ['checks' => []];
  }

  // $distantes : autre fichier pour le selftest (qui ne touche pas au vrai)
  public static function checks($distantes = self::DISTANTES) {
    $liste = [];
    foreach (self::lireJson(self::LOCALES)['checks'] as $c) $liste[$c['id']] = $c;
    foreach (self::lireJson($distantes)['checks'] as $c) {
      // un champ qui n'est pas du texte (tableau…) ferait planter toute la liste en PHP 8
      if (!is_array($c) || !is_string($c['id'] ?? null) || !is_string($c['gravite'] ?? null) || !isset(self::POIDS[$c['gravite']])) continue;
      foreach (self::DISTANT_CHAMPS as $k) if (isset($c[$k])) $c[$k] = is_string($c[$k]) ? strip_tags($c[$k]) : null;
      $c = array_filter($c, fn($v) => $v !== null);
      if (isset($c['reference']) && !preg_match('#^https://#', $c['reference'])) unset($c['reference']); // pas de javascript: dans un lien
      if (isset($liste[$c['id']])) {
        // une base distante peut aggraver une règle locale, pas l'adoucir (sinon elle ferait taire tout l'audit)
        if (self::POIDS[$c['gravite']] > self::POIDS[$liste[$c['id']]['gravite']]) $liste[$c['id']]['gravite'] = $c['gravite'];
      } elseif (self::complete($c)) {
        unset($c['fix'], $c['cmd'], $c['test']);
        $liste[$c['id']] = $c;
      }
    }
    return $liste;
  }

  // Règle distante nouvelle : un type accepté et ses champs, sinon avertissements PHP et « erreur » à chaque audit
  private static function complete($c) {
    if (!is_string($c['titre'] ?? null)) return false;
    if (($c['type'] ?? '') == 'core_version') return is_string($c['max'] ?? null);
    return ($c['type'] ?? '') == 'config' && is_string($c['key'] ?? null) && in_array($c['op'] ?? '', self::OPS, true)
      && (is_scalar($c['value'] ?? null) || $c['op'] == 'empty') && is_string($c['plugin'] ?? 'core');
  }

  public static function evaluer($c) {
    switch ($c['type']) {
      case 'config':
        $v = config::byKey($c['key'], $c['plugin'] ?? 'core', '');
        $p = ['eq' => $v == $c['value'], 'neq' => $v != $c['value'], 'gt' => is_numeric($v) && $v > $c['value'],
              'lt' => is_numeric($v) && $v < $c['value'], 'empty' => $v === '' || $v === null,
              'regex' => @preg_match($c['value'], (string)$v) === 1][$c['op']] ?? null;
        if ($p === null) throw new Exception(sprintf(__('opérateur inconnu %s', __FILE__), $c['op']));
        return [$p, ''];
      case 'core_version':
        $v = jeedom::version();
        return [version_compare($v, $c['max'], empty($c['exclu']) ? '<=' : '<'), sprintf(__('version %s', __FILE__), $v)];
      case 'shell':
        $o = (string)shell_exec('timeout 20 sh -c ' . escapeshellarg($c['cmd']));
        return [preg_match($c['regex'], $o) === 1, ''];
      case 'builtin':
        $m = 'test_' . $c['test'];
        if (!method_exists('secaudit_tests', $m)) throw new Exception(sprintf(__('test inconnu %s', __FILE__), $c['test']));
        return secaudit_tests::$m();
    }
    throw new Exception(sprintf(__('type inconnu %s', __FILE__), $c['type']));
  }
}
