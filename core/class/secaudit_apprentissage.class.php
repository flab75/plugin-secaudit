<?php
/* Apprentissage : chaque chemin visé depuis l'extérieur est retenu (config « chemins_appris »), puis vérifié par le test « chemins_vises ».
   Les scripts PHP absents au moment de l'essai sont retenus à part (« scripts_absents ») : s'ils apparaissent ensuite, c'est peut-être une porte dérobée. */
class secaudit_apprentissage {
  public static function appris() {
    $a = config::byKey('chemins_appris', 'secaudit', []);
    return is_array($a) ? $a : [];
  }

  public static function absents() {
    $a = config::byKey('scripts_absents', 'secaudit', []);
    return is_array($a) ? $a : [];
  }

  public static function apprendre() {
    $appris = self::appris();
    $absents = self::absents();
    foreach (secaudit_journal::essais() as $e) {
      if (secaudit_whois::estLocale($e['ip']) || secaudit_journal::famille($e['chemin']) == 'jeedom') continue;
      $c = mb_substr($e['chemin'], 0, secaudit_historique::LONGUEUR); // un chemin peut faire des Ko
      $appris[$c] = max($appris[$c] ?? 0, $e['t']);
      if ($e['absent'] && strlen($c) < secaudit_historique::LONGUEUR) $absents[$c] = max($absents[$c] ?? 0, $e['t']);
    }
    $absents = array_filter($absents, fn($t) => $t > time() - 90 * 86400); // un faux « apparu » finit par s'effacer
    foreach (['chemins_appris' => $appris, 'scripts_absents' => $absents] as $k => $v) {
      arsort($v);
      config::save($k, array_slice($v, 0, 1000, true), 'secaudit');
    }
    return count($appris);
  }
}
