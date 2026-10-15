<?php
/* Mise à jour de la base des failles connues (NVD + base complémentaire optionnelle) → data/checks_remote.json. */
class secaudit_base {
  const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=jeedom';

  private static function telecharger($url) {
    $ctx = stream_context_create(['http' => ['timeout' => 30, 'header' => "User-Agent: jeedom-secaudit\r\n"]]);
    $t = @file_get_contents($url, false, $ctx);
    if ($t === false) throw new Exception(sprintf(__('téléchargement impossible : %s', __FILE__), $url));
    $j = json_decode($t, true);
    if (!is_array($j)) throw new Exception(sprintf(__('réponse illisible : %s', __FILE__), $url));
    return $j;
  }

  public static function mettreAJour() {
    $locales = array_column(secaudit_regles::lireJson(secaudit_regles::LOCALES)['checks'], 'id');
    $grav = ['CRITICAL' => 'critique', 'HIGH' => 'haute', 'MEDIUM' => 'moyenne', 'LOW' => 'info'];
    $checks = [];
    foreach (self::telecharger(self::NVD)['vulnerabilities'] ?? [] as $v) {
      $cve = $v['cve'];
      if (in_array($cve['id'], $locales)) continue;
      // ponytail: seule la borne haute est lue (versionStart ignoré) → une vieille faille peut être signalée à tort sur une branche ancienne
      foreach ($cve['configurations'] ?? [] as $conf) foreach ($conf['nodes'] ?? [] as $n) foreach ($n['cpeMatch'] ?? [] as $m) {
        if (strpos($m['criteria'] ?? '', ':jeedom:jeedom:') === false) continue;
        $max = $m['versionEndIncluding'] ?? $m['versionEndExcluding'] ?? null;
        if (!$max) continue;
        $sev = '';
        foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $k) if (!$sev && isset($cve['metrics'][$k][0])) $sev = $cve['metrics'][$k][0]['cvssData']['baseSeverity'] ?? $cve['metrics'][$k][0]['baseSeverity'] ?? '';
        $desc = array_values(array_filter($cve['descriptions'] ?? [], fn($d) => $d['lang'] == 'en'))[0]['value'] ?? '';
        $checks[$cve['id']] = ['id' => $cve['id'], 'type' => 'core_version', 'max' => $max, 'exclu' => isset($m['versionEndExcluding']),
          'gravite' => $grav[strtoupper($sev)] ?? 'haute', 'titre' => $cve['id'] . ' : ' . mb_substr(strip_tags($desc), 0, 160),
          'resolution' => 'Mettre Jeedom à jour (Réglages › Système › Centre de mise à jour).', 'reference' => 'https://nvd.nist.gov/vuln/detail/' . $cve['id']];
      }
    }
    // Base complémentaire optionnelle (même format que checks.json), filtrée à la lecture par secaudit_regles::checks()
    $url = trim(config::byKey('checks_url', 'secaudit', ''));
    if ($url !== '' && strpos($url, 'https://') !== 0) throw new Exception(sprintf(__('checks_url doit commencer par https:// : %s', __FILE__), $url));
    if ($url !== '') foreach (self::telecharger($url)['checks'] ?? [] as $c) if (isset($c['id'])) $checks[$c['id']] = $c;

    file_put_contents(secaudit_regles::DISTANTES, json_encode(['date' => date('Y-m-d H:i'), 'checks' => array_values($checks)], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    log::add('secaudit', 'info', 'Base mise à jour : ' . count($checks) . ' règle(s) distante(s)');
    return count($checks);
  }
}
