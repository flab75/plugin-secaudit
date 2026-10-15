<?php
/* Documentation « méthodes et raisons » (docs/fr_FR/methodes.md) affichée dans la page du plugin.
   ponytail: Jeedom n'a pas de convertisseur Markdown ; seul ce qu'utilise la doc est lu (titres, paragraphes, listes, tableaux, gras, code),
   une sous-liste est un simple retrait. Texte échappé avant toute balise. */
class secaudit_doc {
  // Doc dans la langue de Jeedom, en français sinon
  public static function fichier() {
    $f = __DIR__ . '/../../docs/' . config::byKey('language', 'core', 'fr_FR') . '/methodes.md';
    return is_file($f) ? $f : __DIR__ . '/../../docs/fr_FR/methodes.md';
  }

  public static function html($md = null) {
    $md = $md ?? (string)@file_get_contents(self::fichier());
    $en = fn($t) => preg_replace(['/`([^`]+)`/', '/\*\*(.+?)\*\*/'], ['<code>$1</code>', '<strong>$1</strong>'], htmlspecialchars(trim($t), ENT_QUOTES));
    $h = '';
    $bloc = ''; // bloc ouvert : p, ul, table, pre
    $fermer = function () use (&$h, &$bloc) { if ($bloc) $h .= "</$bloc>"; $bloc = ''; };
    $ouvrir = function ($b, $html) use (&$h, &$bloc, $fermer) { if ($bloc != $b) { $fermer(); $h .= $html; $bloc = $b; } };
    foreach (preg_split('/\R/', $md) as $l) {
      if (strpos($l, '```') === 0) { if ($bloc == 'pre') $fermer(); else $ouvrir('pre', '<pre>'); continue; }
      if ($bloc == 'pre') { $h .= htmlspecialchars($l) . "\n"; continue; }
      if (trim($l) === '') { $fermer(); continue; }
      if (preg_match('/^(#{1,4}) (.*)$/', $l, $m)) { $fermer(); $n = strlen($m[1]); $h .= "<h$n>" . $en($m[2]) . "</h$n>"; continue; }
      if (preg_match('/^\|(.*)\|\s*$/', $l, $m)) {
        if (preg_match('/^[\s|:-]+$/', $m[1])) continue; // ligne de séparation
        $t = $bloc == 'table' ? 'td' : 'th';
        $ouvrir('table', '<table class="table table-condensed table-bordered">');
        $h .= '<tr>' . implode('', array_map(fn($c) => "<$t>" . $en($c) . "</$t>", explode('|', $m[1]))) . '</tr>';
        continue;
      }
      if (preg_match('/^( *)(?:[-*]|\d+\.) (.*)$/', $l, $m)) {
        $ouvrir('ul', '<ul>');
        $h .= '<li' . (strlen($m[1]) ? ' style="margin-left:' . 1.5 * intdiv(strlen($m[1]), 2) . 'em"' : '') . '>' . $en($m[2]);
        continue;
      }
      if ($bloc == 'ul' || $bloc == 'p') { $h .= ' ' . $en($l); continue; } // suite de l'élément ou du paragraphe
      $ouvrir('p', '<p>');
      $h .= $en($l);
    }
    $fermer();
    return $h;
  }
}
