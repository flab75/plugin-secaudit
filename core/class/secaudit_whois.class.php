<?php
/* Qui est derrière une IP : propriétaire (whois, gardé 30 jours) et profil deviné.
   Le whois prend jusqu'à 10 s : la page ne lit que le cache (proprietaire), c'est le cron horaire qui interroge (identifier). */
class secaudit_whois {
  const GARDE = 30 * 86400;
  const PROFILS = [
    ['#palo alto|censys|shodan|shadowserver|onyphe|stretchoid|leakix|binaryedge|internet-measurement|criminalip|recyber#i', 'scanner d\'une société de sécurité (recensement, plutôt inoffensif)'],
    ['#vpn|ivacy|nordvpn|surfshark|proton|m247|datacamp#i', 'VPN (le vrai auteur est masqué)'],
    ['#microsoft|amazon|google|digitalocean|linode|akamai|ovh|hetzner|oracle|alibaba|tencent|vultr|scaleway|contabo|business|entreprise|cloud|hosting|datacenter|data center#i', 'serveur loué chez un grand hébergeur (robot)'],
    ['#telecom|orange|sfr|bouygues|free sas|free mobile|proxad|vodafone|comcast|verizon|retail|dsl|cable|broadband|residential|dynamic#i', 'connexion de particulier (machine probablement infectée)'],
  ];

  public static function profil($org) {
    foreach (self::PROFILS as [$re, $t]) if (preg_match($re, $org)) return $t;
    return 'propriétaire non reconnu'; // profils comparés (estVous) : traduits à l'affichage seulement
  }

  // Réseau privé, réservé ou Tailscale (100.64.0.0/10)
  public static function estLocale($ip) {
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || preg_match('/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./', $ip);
  }

  private static function cache() {
    $c = config::byKey('whois', 'secaudit', []);
    return is_array($c) ? $c : [];
  }

  // Lecture seule : ce qu'on sait déjà de l'IP
  public static function proprietaire($ip) {
    if (self::estLocale($ip)) return ['org' => __('réseau local / Tailscale', __FILE__), 'pays' => '', 'profil' => 'chez vous'];
    return self::cache()[$ip] ?? ['org' => '', 'pays' => '', 'profil' => 'pas encore identifiée (whois chaque heure)'];
  }

  // À interroger : IP publique absente du cache ou fiche périmée (30 jours ; 1 jour pour un whois muet)
  public static function aIdentifier($ip) {
    $c = self::cache()[$ip] ?? null;
    return !self::estLocale($ip) && (!$c || $c['t'] < time() - (empty($c['muet']) ? self::GARDE : 86400));
  }

  // Interroge whois. false = whois muet : noté pour ne réessayer que demain (sinon il bloquerait la file chaque heure)
  public static function identifier($ip) {
    if (!self::aIdentifier($ip)) return true;
    $cache = self::cache();
    $w = mb_scrub((string)shell_exec('timeout 10 whois ' . escapeshellarg($ip) . ' 2>/dev/null'), 'UTF-8'); // Latin-1, EUC-KR… : json_encode échouerait et le cache serait vidé
    $champ = function ($re) use ($w) {
      return preg_match_all('/^(?:' . $re . '):\s*(\S.*)$/mi', $w, $m) ? trim(end($m[1])) : '';
    };
    $org = $champ('org-name|OrgName|Organization');
    if ($org === '' || preg_match('/RIPE|APNIC|Asia Pacific Network|LACNIC|AFRINIC|ARIN/i', $org)) $org = $champ('netname|NetName') ?: $champ('descr');
    if ($org === '') {
      // vraie date : avec une date vieillie, la fiche serait la première coupée du cache plein et l'IP réinterrogée chaque heure
      $r = ['org' => '', 'pays' => '', 't' => time(), 'muet' => true, 'profil' => 'whois muet (nouvel essai demain)'];
    } else {
      $r = ['org' => $org, 'pays' => strtoupper($champ('country|Country')), 't' => time()];
      // ponytail: pas de DNS inverse (lent, et son nom est choisi par l'attaquant : « shodan » le ferait passer pour inoffensif)
      $r['profil'] = self::profil($org . ' ' . $champ('descr|netname|NetName'));
    }
    $cache[$ip] = $r;
    uasort($cache, fn($a, $b) => $b['t'] <=> $a['t']);
    config::save('whois', array_slice($cache, 0, 300, true), 'secaudit');
    return $org !== '';
  }
}
