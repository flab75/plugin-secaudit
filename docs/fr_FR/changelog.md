# Changelog

## 0.28 (2026-10-24)
Faux positifs signalés sur le forum :
- `maj_jeedom` : le constat nomme les mises à jour en attente (« Jeedom » pour le core) ; un plugin à mettre à jour se lisait « Jeedom pas à jour ».
- `mqtt_anonyme` : le broker est interrogé (connexion MQTT sans identifiant sur ses ports ouverts au réseau) au lieu de chercher `allow_anonymous true` dans les fichiers, qui se trompait sur un fichier non chargé ou un listener local seulement. Le client « secaudit » refusé apparaît donc dans le journal du broker à chaque audit. Ports sondés : processus mosquitto, port 1883, conteneur Docker mosquitto / emqx ou de port interne 1883 ; sans sudo, port 1883 seulement ; 8883 / 8884 (TLS) non sondés.

## 0.27 (2026-10-23)
Suite de Jeedom 4.6.2 :
- `jeedom_4_6_2` : Jeedom antérieur à 4.6.2 signalé (protections PHP contre une faille connue, protections PHP ajoutées à la configuration de sécurité d'Apache).
- `apache_security` : signale les lignes de la configuration de sécurité livrée par Jeedom (`install/apache_security`) absentes de `security.conf` actif, ou `security.conf` désactivé ou son lien cassé (Apache seulement ; avant la 4.5, ou sans `jeedom.com` dans `security.conf`, ou `security.conf` de conf-enabled qui n'est pas un lien, le constat précise que Jeedom ne recopie pas ce fichier).
- Les boutons « Assistant » et « Ajouter mon adresse actuelle » passent du `onclick` au fichier JavaScript du plugin (prêts pour une politique de sécurité du contenu plus stricte).
- Revue adverse : lignes comptées avec leurs répétitions (les `php_admin_*` sont dans deux blocs), configuration active lue, illisible = erreur, rien sans Apache.

## 0.26 (2026-10-15)
Diagnostics affinés à partir de cas réels (Homebridge refusé par l'API, conteneur Signal ouvert au réseau, MariaDB de Debian 12) :
- `ssh_password` : le constat dit combien de clés SSH sont installées et qui se connecte encore par mot de passe (30 j) ; la résolution prévient qu'il ne faut pas couper sans clé.
- `mysql_ecoute` : détecte le port ouvert par `mariadb.socket` (systemd, Debian 12), où `bind-address` est ignoré ; la résolution dit de désactiver le socket.
- `zwavejs_ui` : signalé seulement si l'API répond sans authentification ou si rien ne permet de le vérifier (un 8091 ouvert mais protégé n'est plus un problème).
- `ports_ouverts` : nomme le conteneur Docker et son équipement Docker management, dit si le port répond sans mot de passe ; la résolution explique `127.0.0.1:PORT` dans Docker management (et qu'un plugin peut le réécrire). L'assistant liste les ports sans les sonder.
- `api_refus` : nomme le client refusé (plugin, adresse), le nombre de refus et à qui appartient la clé (compte désactivé…), jamais la clé ; un client réparé sort du constat aussitôt. Résolution : redémarrer le démon du plugin quand sa clé est celle d'un compte désactivé.
- `ss` sans sudo : les ports restent vus, mais sans les noms de processus : un nom mis dans « Ports acceptés » (homebridge) ne filtre plus rien, le constat le dit.
- Revue adverse : `api_refus` compte par adresse (un nom de plugin changé à chaque essai ne passe plus sous le seuil) et signale 10 refus venus d'Internet en 24 h ; un refus par requête ; lignes de refus sans horodatage strict ignorées. `ports_ouverts` ne sonde plus que Docker et les serveurs web connus (pas un pont série ni le socket d'un démon), « page web servie » au lieu de « sans mot de passe » sur `/`, plages de ports Docker lues. `ssh_password` teste aussi `KbdInteractiveAuthentication`, lit le journal `sshd` et date sa plus vieille ligne ; résolution dans `sshd_config.d`. `mysql_ecoute` : résolution simplifiée (désactiver `mariadb.socket`), « processus inconnu » sans sudo.
- Revue adverse (2e tour) : `api_refus` garde les refus d'une requête sur plusieurs lignes (entrée à part, 20 refus en 24 h signalés même sans adresse), ne remet plus le compteur à zéro sur une autre erreur, exclut 100.64.0.0/10 (Tailscale) des refus d'Internet, signale des « adresses falsifiables » si `entetes_ip` est en défaut. `ports_ouverts` : chaque port d'une plage Docker, conteneur sondé seulement si son image est connue ou son port interne web, code HTTP affiché quand ce n'est ni 2xx ni 401/403, `docker ps` limité à 10 s. `ssh_password` : clés comptées par compte, journal `sshd-session` (OpenSSH 9.8+), `journalctl` limité à 10 s.
- Revue adverse (3e tour) : refus sans requête lisible comptés seulement sur 24 h (plus de faux positif durable), rattachement par IP plus solide face aux lignes forgées, « adresses falsifiables » aussi pour `remoteip`, `zwavejs_ui` dit « authentification désactivée », `ssh_password` signale un journal coupé par le délai et lit les clés sans saut de ligne final.

## 0.25 (2026-10-15)
- Correctif `fichiers_publics` retiré : le plugin ne déplace plus de fichiers hors de son dossier (règle du market Jeedom). Le point reste signalé, la résolution dit quoi faire à la main.
- Doc : section « Données et confidentialité » (ce qui sort de la machine, ce qui est gardé et combien de temps).

## 0.24 (2026-10-15)
- Règle `remoteip` : signalée seulement si le module remoteip d'Apache est activé (un `remoteip.conf` laissé par une mise à jour, module désactivé, donnait un faux positif).

## 0.23 (2026-10-14)
- Textes générés traduisibles : rapport (titres des règles, constats, « comment résoudre », gravités), résumé et alerte des tentatives, profils whois, « ce qu'elle cherchait », widget, messages d'erreur. Ils suivent la langue de Jeedom (`core/i18n/en_US.json`) ; en français, rien ne change (« Aucun problème grave » compris).
- `tests/selftest.php en_US` : essai à blanc avec les textes en anglais (contrôle de la traduction en plus).

## 0.22 (2026-10-14)
- Version anglaise : interface (`core/i18n/en_US.json`), documentation `docs/en_US/` (mode d'emploi, méthodes, changelog). La fenêtre **Documentation** suit la langue de Jeedom (français à défaut). Le rapport, les règles et les alertes restent en français.

## 0.21 (2026-10-14)
- Dépendance `whois` déclarée (`plugin_info/packages.json`) : Jeedom l'installe et affiche son état.
- Liens documentation et changelog (branches master et beta) dans `info.json`.
- Dépôt GitHub `flab75/plugin-secaudit` avec les workflows Jeedom (lint PHP 7.4 / 8.0 / 8.2).

## 0.20 (2026-10-14)
- Documentation complète « méthodes et raisons » (`docs/fr_FR/methodes.md`) : comment chaque partie fonctionne et pourquoi. Bouton « Documentation » sur la page du plugin.

## 0.19 (2026-10-14)
- Assistant de préconfiguration sur la page du plugin (première visite après l'installation ou cette mise à jour, puis bouton « Assistant ») : widget, liste blanche, ports acceptés, box vérifiée, premier audit. Documenté (« Assistant de préconfiguration »).

## 0.18 (2026-10-14) — corrections de la douzième revue adverse
- Selftest : la liste noire temporaire n'est posée que si la vraie est vide, et remise sans revérification ; un échec ne la laisse plus en place.

## 0.17 (2026-10-14) — corrections de la onzième revue adverse
- Listes : seules les entrées ajoutées sont vérifiées (une ancienne en conflit ne bloque plus les ajouts).
- Selftest : liste noire temporaire pour tester le refus d'une entrée blanche couverte.
- whiteips_large : saut de ligne final signalé (masque + saut de ligne = erreur PHP dans netMatch).

## 0.16 (2026-10-14) — corrections de la dixième revue adverse
- whiteips_large : tabulation lue comme netMatch (signalée), adresse exacte comparée après trim.
- Liste blanche : nouvelle entrée couverte par la liste noire refusée ; liste inchangée non revérifiée.
- Bouton « Voir l'audit » sur le dashboard seulement (pas les designs).

## 0.15 (2026-10-14) — corrections de la neuvième revue adverse
- whiteips_large : bornes de plage, IP et masque validés (une borne illisible fait couvrir presque tout l'IPv4 à netMatch).
- Correctif API en IP blanche : entrées illisibles sautées (erreur PHP).
- Lancer refusé aussi à un non-admin via l'API (clé utilisateur).
- Liste noire refusée si elle couvre votre adresse actuelle ou votre liste blanche.
- Effacer l'alerte possible quand fail2ban ne répond pas ; ses bans oubliés après 7 jours.
- Script apparu excusé par une mise à jour du core seulement dans les dossiers du core.
- Avertissement du correctif whiteips : IPv6 et entrées illisibles.
- Widget : équipement supprimé à la main recréé à l'enregistrement de la configuration.

## 0.14 (2026-10-14)
- Widget : bouton « Voir l'audit » vers la page du plugin.

## 0.13 (2026-10-14) — corrections de la huitième revue adverse
- Liste noire sans limite de largeur ; entrées de liste blanche ignorées affichées sur la page.
- `whiteips_large` devient un test intégré qui lit les entrées comme `netMatch` (espaces, `/08`, `/-1`) ; en IPv6 seules les adresses exactes passent (étoile, plage, réseau). `api_whiteip` saute les entrées IPv6.
- `chemins_vises` : core excusé par une mise à jour faite après la demande (mtime de `core/config/version`) ; plugins par un contenu plus ancien que la demande.
- Widget : `lancer` refusé à un compte non admin ; l'objet n'est réappliqué que s'il change ; un objet supprimé masque le widget au lieu de bloquer la configuration.
- Débannir : la réponse de fail2ban est lue en dernière ligne, un échec est journalisé ; fail2ban muet : ses bans ne sont pas purgés.

## 0.12 (2026-10-14) — corrections de la septième revue adverse
- `chemins_vises` : un script apparu n'est excusé que si son contenu est plus ancien que la demande du robot (mtime) ; le ctime, remis à zéro par la réparation des droits de Jeedom, ne sert plus.
- Listes : réseau au plus /24 (IPv4) ou /48 (IPv6) ; une entrée plus large saisie avant est ignorée.
- Résumé : une IP de la liste blanche qui a cherché autre chose que Jeedom est comptée avec les adresses extérieures.
- Liste blanche trop large : seuls `127.0.0.1`, `127.0.0.0/8` et `127.*.*.*` sont exemptés (`127.0.0.1/0` signalé) ; réseaux IPv6 plus larges qu'un /48 signalés.
- Bouton « Effacer l'alerte » pour un ban déjà levé ; un Débannir fail2ban en échec est signalé ; un ban actif garde sa première vue au-delà de 30 h.

## 0.11 (2026-10-14)
- Bouton **Configuration** sur la page du plugin.
- Commande `graves` (problèmes critiques et hauts) et widget : objet d'affichage choisi dans la configuration.

## 0.10 (2026-10-14) — corrections de la sixième revue adverse
- Listes : réseau au plus /16 (IPv4) ou /32 (IPv6). Alerte : « attention, a aussi cherché … » si l'IP n'a pas demandé que du Jeedom.
- Whois muet daté pour de vrai (n'est plus coupé du cache plein ni réinterrogé chaque heure) ; pas de whois pour les listes ni pour les bans sshd seuls sans essai.
- Offres pro / cloud des opérateurs (Orange Business…) classées hébergeur, plus particulier.
- `chemins_vises` : un script apparu n'est excusé que s'il est arrivé avec la mise à jour du plugin ou du core (à 10 min près) ; oubli après 90 jours.
- Liste blanche trop large : `127.0.0.0/8` accepté ; plages `a-b` hors d'un /24 et masques `/255.x` larges signalés.
- Bans vus datés de leur première vue (plus d'alerte le surlendemain) ; Débannir recalcule l'alerte ; une erreur d'apprentissage ou de whois n'empêche plus le recalcul horaire.

## 0.9 (2026-10-14) — listes blanche et noire, corrections de la cinquième revue adverse
- Configuration : **liste blanche** (vos adresses hors de chez vous : bannies → alerte toujours) et **liste noire** (jamais prises pour vous). IP ou CIDR, IPv4/IPv6, vérifiées à l'enregistrement. Elles ne bannissent ni ne débannissent rien.
- « Sans doute vous » seulement pour une connexion de particulier française (ou la liste blanche) : plus jamais pour un propriétaire non reconnu ou un whois muet. Un ban sshd / recidive seul ne déclenche plus l'alerte.
- `/plugins/<x>/…` n'est un appel Jeedom que si le plugin x est installé.
- Alerte datée (« vue bannie le … ») : un ban de 7 h 10 relu le lendemain à 8 h se reconnaît.
- `chemins_vises` : un script PHP absent quand un robot l'a demandé et présent maintenant est signalé (porte dérobée ?), sans jamais l'exécuter.
- Liste blanche trop large : `192.*.1.*` et toute étoile avant le dernier octet. `api_whiteip` accepte `127.0.0.0/8` (lu avec `netMatch` de Jeedom).
- Note : pour Jeedom, une étoile vaut un /24 quelle que soit sa place (`10.*` ne couvre pas 10.1.2.3) : écrire les réseaux en CIDR.
- Base distante : ne peut plus réécrire le texte d'une règle locale (seulement l'aggraver) ; une nouvelle règle doit avoir titre, clé, opérateur connu (ou version max).

## 0.8 (2026-10-14) — corrections de la quatrième revue adverse
- « Sans doute vous » jamais pour un hébergeur, un scanner, un VPN ou une IP pas encore identifiée (ni pour un ban Jeedom depuis un hébergeur français).
- Famille « appels Jeedom » limitée aux vrais points d'entrée (`core/ajax|php|api`, `desktop/php|modal`, plugins idem, `/mobile/`, fichiers statiques).
- Bans vus gardés 30 h (le rapport de 8 h peut lire l'alerte de 7 h). Débannir les efface, ainsi que le compteur d'échecs Jeedom de l'IP.
- `cron5` ne relit que les bans Jeedom (plus de sudo fail2ban toutes les 5 min) ; 6 whois par heure au plus.
- Règle `entetes_ip` : les 4 en-têtes, et mod_remoteip doit être désactivé.
- Liste blanche trop large : toute entrée plus large qu'un /24 ; le correctif utilise la même regex.
- Chemins appris tronqués à 200 caractères ; `chemins_vises` saute aussi .phtml, .phar, .phps.
- `sauvegardes.json` sous verrou, ancienne valeur aussi dans le log.
- README réduit à un renvoi vers la doc ; doc corrigée.

## 0.7 (2026-10-14) — corrections de la troisième revue adverse
- Les bans Jeedom (10 min) sont notés toutes les 5 min (`cron5`, clé `bans_vus`, 24 h) : l'alerte du matin voit aussi un ban déjà levé.
- Whois des IP bannies par Jeedom en premier (leur pays décide de l'alerte).
- Un robot hébergé ou un scanner qui ne demande que des scripts Jeedom n'est plus pris pour vous (alerte et résumé).
- Fichiers statiques Jeedom (`/core/img/…`, `/favicon.ico`…) classés « appels Jeedom ».
- Texte non UTF-8 (whois, chemins) nettoyé : l'historique et le cache whois ne peuvent plus échouer à l'enregistrement.
- HTML retiré des textes de la base distante et des CVE.
- Correctif « API en IP blanche » : ne touche que l'API de la règle cliquée, refuse si 127.0.0.1 manque à la liste blanche.
- Avertissement avant de réduire la liste blanche (Docker, VPN).
- Nouvelle règle `entetes_ip` : Apache doit supprimer X-Forwarded-For & co., que Jeedom croit pour l'IP du client.

## 0.6 (2026-10-14) — corrections de la seconde revue adverse
- L'alerte « IP bannie qui est sans doute vous » est recalculée chaque heure (clé `tentatives`), plus seulement par l'audit de minuit : le rapport du matin est à jour.
- Alerte aussi pour une IP bannie par Jeedom (mots de passe ratés) sans aucun essai suspect, depuis la France ou une connexion de particulier.
- Familles comptées sur tous les essais d'une IP (plus seulement les 20 chemins gardés en exemple) ; `/mobile/` et les dossiers Jeedom = appels Jeedom.
- Historique dans `data/historique.json` sous verrou (la page et les crons l'écrivaient en même temps : essais perdus ou comptés deux fois).
- Une ligne du journal ne peut plus être fabriquée par le referer d'une requête.
- Refus `Require all denied` (AH01630) et `AH00128` lus.
- Une base distante ne peut plus adoucir la gravité d'une règle locale ; `checks_url` en https seulement.
- Whois muet : réessayé le lendemain au lieu de bloquer la file chaque heure.
- Bans Jeedom expirés ignorés ; IP bannies sans essai plus comptées comme « ayant sondé ».
- Correctif API : la confirmation prévient que les applis externes seront refusées.
- Erreurs PHP 8 rattrapées (ajax, page).

## 0.5 (2026-10-14) — corrections de la revue adverse
- Une attaque visant Jeedom (`/core/.env`, `/plugins/…/database.db`) n'est plus classée « appel Jeedom légitime » : cette famille ne couvre plus que les scripts `.php` absents, testée en dernier.
- Historique par IP sur 30 jours (`secaudit_historique`) : le journal `http.error` étant ramené à ~500 lignes par Jeedom, l'analyse ne couvrait qu'une journée.
- Les IP qui n'ont demandé que des scripts Jeedom absents (vous en déplacement, une appli) ne sont plus comptées comme attaquantes ; si l'une est bannie → alerte (page et rapport du matin).
- Le whois se fait au cron horaire (20 IP au plus), plus pendant l'affichage de la page ; un whois muet n'est plus mis en cache 30 jours ; plus de DNS inverse (choisi par l'attaquant).
- Profil par défaut « propriétaire non reconnu » (au lieu de « robot ») ; Free/Proxad reconnus comme connexions de particuliers.
- Liste des IP jamais bannies lue correctement (elle contenait des bouts de mots).
- Résumé : « Les essais visibles dans le journal ont été refusés… » au lieu de « Tous ces essais ont échoué ».
- Base distante : liens `https://` seulement, champs non texte ignorés (ils faisaient planter la liste des règles).
- Correctif liste blanche : retire seulement les entrées trop larges au lieu d'écraser la liste ; correctif fichiers publics : signale les fichiers non déplacés.
- Selftest : le garde-fou utilise un fichier temporaire au lieu de réécrire `data/checks_remote.json`.

## 0.4 (2026-10-14)
- Code découpé en modules d'une seule tâche (`core/class/secaudit_*.class.php`) : règles, tests, base, correctifs, bans, journal, whois, tentatives, résumé, apprentissage.
- Correction : la section « Tentatives » plantait (PHP 8.1, `array_merge` sur un tableau indexé par IP).

## 0.3 (2026-10-14)
- Analyse des tentatives : chaque IP qui sonde Jeedom (http.error) est identifiée (whois, profil : scanner, hébergeur, VPN, particulier), son objectif deviné (vol de secrets, porte dérobée…), avec un résumé en français.
- Apprentissage : les chemins visés sont retenus chaque heure ; nouvelle règle `chemins_vises` (28 règles) qui vérifie qu'aucun n'est servi ici.
- Rapport du matin : ligne « Tentatives ».

## 0.2 (2026-10-14)
- Section « Bannissements » : IP bannies par fail2ban (toutes les prisons) et par Jeedom, cause lue dans http.error, journal fail2ban, bouton Débannir.

## 0.1 (2026-10-13)
- Première version : 27 règles, mise à jour NVD, 3 correctifs, essai à blanc.
