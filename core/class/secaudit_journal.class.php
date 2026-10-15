<?php
/* Lecture de /var/www/html/log/http.error : essais (date, IP, chemin) et objectif deviné d'après le chemin. */
class secaudit_journal {
  // Objectif d'un essai, deviné d'après le chemin demandé (premier motif qui correspond).
  // « jeedom » en dernier et seulement pour un .php : /core/.env ou /plugins/x/data/base.db sont des attaques, pas des appels Jeedom.
  const FAMILLES = [
    'secrets' => ['#\.env|config\.(php|json|ya?ml|js)|wp-config|\.git|\.svn|\.aws|\.ssh|id_rsa|credential|secret|\.npmrc|\.m2|gradle|\.htpasswd|\.sql|backup|\.bak|dump|\.(db|sqlite3?)$#i', 'vol de secrets (fichiers de configuration, mots de passe, sauvegardes)'],
    'portes'  => ['#shell|cmd\.php|wso|alfa|c99|r57|hello_world|up\.php|upload\.php|xleet|bypass|\.well-known/.+\.php#i', 'recherche d\'une porte dérobée laissée par un autre pirate'],
    'diag'    => ['#actuator|debug|server-status|server-info|phpinfo|info\.php|_profiler|telescope|_ignition|console#i', 'pages de diagnostic oubliées (révèlent la configuration)'],
    'admin'   => ['#adminer|phpmyadmin|pma|myadmin|sqlite|mysql|manager/html|solr|jenkins#i', 'outils d\'administration ou bases de données exposés'],
    'cms'     => ['#wp-|wordpress|xmlrpc|joomla|drupal|magento#i', 'recherche d\'un site WordPress ou autre CMS'],
    'equip'   => ['#cgi-bin|\.cgi|boaform|hnap|goform|mifs|/owa|/ecp|autodiscover|vpn|remote/|global-protect|fortinet|citrix|\.aspx?$#i', 'failles d\'équipements réseau ou de logiciels connus'],
    // Points d'entrée PHP de Jeedom et de ses plugins (pas n'importe quel .php : /plugins/x/server/php/index.php est une faille connue),
    // l'appli mobile, les images/styles/scripts des dossiers Jeedom, l'icône du site
    'jeedom'  => ['#^/((plugins/[\w-]+/)?(core/(ajax|php|api)|desktop/(php|modal))/[\w.-]+\.php|mobile/.*|(core|plugins|desktop|mobile|3rdparty)/.*\.(png|jpe?g|svg|gif|ico|css|js|woff2?|map)|favicon\.ico|apple-touch-icon[\w-]*\.png)$#', 'appel Jeedom vers un script absent (souvent un navigateur ou une appli légitime)'],
  ];

  public static function famille($chemin) {
    foreach (self::FAMILLES as $k => [$re, $t]) {
      // /plugins/x/… n'est un appel Jeedom que si le plugin x est installé ici (sinon : un robot qui cherche un plugin vulnérable)
      if ($k == 'jeedom' && preg_match('#^/plugins/([\w-]+)/#', $chemin, $m) && !is_dir(__DIR__ . '/../../../' . $m[1])) continue;
      if (preg_match($re, $chemin)) return $k;
    }
    return 'autre';
  }

  // Affichage seulement (les clés de famille servent aux comparaisons) : traduit dans la langue de Jeedom
  public static function texte($famille) {
    return __(self::FAMILLES[$famille][1] ?? 'chemins divers', __FILE__);
  }

  // Ligne de http.error : refus Apache, script ou fichier absent → [date, ip, chemin, absent = script PHP inexistant au moment de l'essai]
  // [client] doit suivre directement les autres crochets d'en-tête : sinon un referer « [client 192.168.1.20:1] script '…' » fabriquerait un essai
  public static function lireEssai($l) {
    if (!preg_match('/^\[\w+ (\w+) (\d+) ([\d:]+)\.\d+ (\d+)\](?: \[[^\]]*\])*? \[client ([^\]]+):\d+\] (?:AH0(?:1797|1630): client denied by server configuration: |AH01276: Cannot serve directory |script \'|(?:AH00128: )?File does not exist: )\/var\/www\/html([^\s\',:]*)/', $l, $m)) return null;
    return ['t' => strtotime("$m[2] $m[1] $m[4] $m[3]"), 'ip' => $m[5], 'chemin' => mb_scrub($m[6] ?: '/', 'UTF-8'), 'absent' => strpos($m[0], "script '") !== false];
  }

  // Essais des 20 000 dernières lignes, du plus ancien au plus récent
  public static function essais() {
    return array_values(array_filter(array_map([__CLASS__, 'lireEssai'], explode("\n", (string)shell_exec('tail -n 20000 /var/www/html/log/http.error 2>/dev/null')))));
  }
}
