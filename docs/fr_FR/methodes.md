# Audit sécurité : méthodes et raisons

Ce document explique comment le plugin travaille et pourquoi il a été construit ainsi. Le mode d'emploi court est dans `docs/fr_FR/index.md`.
Chaque « Pourquoi » répond à un problème réel rencontré pendant la mise au point, la plupart du temps relevé par une revue adverse (voir le changelog).

## 1. Principes

- **Constater, pas agir.** L'audit lit la configuration et le système, il ne change rien. Les seules modifications sont les deux correctifs, lancés à la main par un administrateur après confirmation, avec sauvegarde de l'ancienne valeur. Pourquoi : un outil de sécurité qui modifie seul la machine peut couper l'accès (API, SSH, liste blanche) au moment où personne ne regarde.
- **Rien ne sort de la machine**, sauf trois requêtes : le téléchargement de la base des failles (NVD), la base complémentaire si vous en donnez une, et les requêtes `whois` sur les IP qui ont sondé Jeedom. Le rapport, l'historique et les listes restent en local.
- **Réservé aux administrateurs.** La page, l'ajax et la commande « Lancer » vérifient le profil admin. Pourquoi : le rapport décrit vos failles, et sur une installation Jeedom standard un administrateur Jeedom est root sur la machine (voir la règle `sudo_www`).
- **Une donnée venue de l'extérieur n'est jamais du code.** Ni la base téléchargée, ni les chemins demandés par les robots, ni les réponses whois ne peuvent déclencher une commande ou injecter du HTML.
- **Les limites connues sont écrites dans le code** (commentaires `ponytail:`) et reprises au chapitre 14, au lieu d'être cachées.

## 2. Organisation du code

La classe `secaudit` (fichier `core/class/secaudit.class.php`) porte l'équipement, le lancement de l'audit, les crons et l'assistant. Chaque tâche est dans son propre module, chargé automatiquement :

| Module | Rôle |
|---|---|
| `secaudit_regles` | lit les règles (locales et téléchargées), filtre la base distante, évalue une règle |
| `secaudit_tests` | tests intégrés (type `builtin`) : chacun renvoie [problème ?, détail] |
| `secaudit_base` | télécharge les failles connues (NVD) et la base complémentaire |
| `secaudit_correctifs` | les deux correctifs et la sauvegarde des anciennes valeurs |
| `secaudit_journal` | lit `log/http.error` et devine l'objectif de chaque essai |
| `secaudit_historique` | garde les essais par IP sur 30 jours |
| `secaudit_whois` | propriétaire d'une IP et profil deviné |
| `secaudit_bans` | bannissements fail2ban et Jeedom, mémoire des bans vus, débannissement |
| `secaudit_tentatives` | croise historique, bans et whois pour la page et le rapport |
| `secaudit_resume` | résumé en français et alerte « sans doute vous » |
| `secaudit_listes` | listes blanche et noire de la configuration |
| `secaudit_apprentissage` | retient les chemins visés par l'extérieur |
| `secaudit_doc` | affiche ce document dans la page du plugin |

Pourquoi des modules : chaque partie se relit et se teste seule, et une erreur dans l'une (whois, journal) n'empêche pas les autres de tourner.

## 3. Ce qui tourne, et quand

| Cron | Ce qu'il fait | Pourquoi cette fréquence |
|---|---|---|
| toutes les 5 min (`cron5`) | note les bans Jeedom en cours | un ban Jeedom dure 10 min par défaut : le cron horaire ne le verrait presque jamais. fail2ban n'est pas relu ici (sudo toutes les 5 min remplirait `auth.log`) ; ses bans durent des heures, le cron horaire suffit |
| chaque heure (`cronHourly`) | apprentissage des chemins, whois (6 IP au plus), recalcul du résumé et de l'alerte | Jeedom ramène `http.error` à quelques centaines de lignes : relu chaque heure, rien ne se perd. L'alerte doit être fraîche pour le rapport du matin |
| chaque nuit (`cronDaily`) | mise à jour de la base des failles, puis audit complet | l'audit prend environ une minute (commandes shell, sudo, requêtes locales) : une fois par jour suffit pour une configuration qui change peu |

Chaque étape du cron horaire est protégée séparément : une erreur d'apprentissage ou de whois est notée dans le log `secaudit` mais n'empêche pas le recalcul de l'alerte. Sinon le rapport du matin lirait l'alerte de l'heure d'avant sans le savoir.

## 4. L'audit

### Les règles
Chaque règle a un identifiant, un titre, une gravité, une résolution et un type :

| Type | Méthode | Exemple |
|---|---|---|
| `config` | compare une clé de configuration Jeedom à une valeur (opérateurs eq, neq, gt, lt, empty, regex) | API HTTP en mode « enable » |
| `core_version` | compare la version du core à une version maximale (incluse ou exclue) | failles connues (CVE) |
| `shell` | lance une commande (20 s au plus) et cherche un motif dans sa sortie | `sshd -T` pour la configuration SSH réelle |
| `builtin` | appelle un test écrit en PHP dans `secaudit_tests` | double authentification des admins |

Une règle qui plante donne l'état « erreur » avec le message, sans arrêter les autres.

### Le score
Le score part de 100 et chaque problème retire des points : critique 25, haute 10, moyenne 4, info 0. Pourquoi ces poids : un seul point critique (accès root possible depuis Internet) doit faire tomber le score sous 80 ; quatre problèmes moyens pèsent moins qu'un problème haut ; les points « info » décrivent sans juger (plateforme, sudo standard, rappel de la box) et ne doivent pas punir une installation normale.

### Messages
Un problème **nouveau** de gravité haute ou critique crée un message Jeedom (comparaison avec le rapport précédent). Pourquoi seulement nouveau : un message chaque nuit pour le même point serait vite ignoré.

### Ce que vérifie chaque règle

| Règle | Gravité | Méthode | Pourquoi |
|---|---|---|---|
| `plateforme` | info | `systemd-detect-virt`, modèle du Raspberry, `/.dockerenv`, `/etc/os-release` | lire les autres points dans leur contexte : sur une VM, la sécurité dépend aussi de l'hôte que le plugin ne voit pas |
| `admins_2fa` | haute | profils admin actifs sans double authentification | admin Jeedom = root (sudo sans mot de passe) : un mot de passe volé suffit à prendre la machine |
| `users_disabled` | info | comptes désactivés encore présents | un compte oublié peut être réactivé ; à supprimer plutôt |
| `api_http`, `api_jsonrpc`, `api_tts` | haute / moyenne | mode de l'API = « enable » (ouvert à toute adresse avec la clé) | une clé API fuit facilement (raccourcis, captures, applis) ; en « IP blanche », une clé volée ne sert à rien hors de vos adresses |
| `whiteips_large` | moyenne | entrées de la liste blanche Jeedom plus larges qu'un /24, lues comme le fait Jeedom (chapitre 7) | une adresse de la liste blanche n'est jamais bannie : `10.*` ou un /16 offre l'essai illimité des mots de passe |
| `ban_seuil` | moyenne | plus de 10 échecs de connexion avant bannissement | au-delà, le bannissement ne freine plus un essai de mots de passe |
| `https_externe` | haute | accès externe déclaré en `http://` | mots de passe et clé API circuleraient en clair |
| `certificat` | haute | certificat du HTTPS local expirant dans moins de 21 jours | certbot renouvelle à 30 jours : à 21, le renouvellement automatique a déjà échoué au moins une fois |
| `maj_jeedom` | moyenne | mises à jour du core et des plugins en attente | les failles corrigées sont publiques après la mise à jour |
| `maj_securite_debian` | moyenne | `apt-get -s upgrade` (simulation, rien n'est installé), paquets venant du dépôt security | idem pour le système |
| `fichiers_publics` | moyenne | fichiers .js, .css, .html, .htm, .txt à la racine de `data/` | Apache les sert sans connexion : sauvegardes ou exports y deviennent lisibles depuis Internet |
| `chemins_vises` | haute | chapitre 11 | une tentative réussie n'apparaît pas dans le journal des erreurs : il faut aller voir |
| `entetes_ip` | haute | absence de `RequestHeader unset` pour X-Forwarded-For, X-Real-IP, CF-Connecting-IP, Client-IP, ou mod_remoteip actif | Jeedom lit ces en-têtes pour connaître l'IP du client : un attaquant qui les envoie choisit son IP et contourne bannissement et liste blanche |
| `ssh_root` | haute | `sshd -T` (configuration réellement appliquée, fichiers inclus) : `permitrootlogin yes` | root est le premier compte essayé par les robots |
| `ssh_password` | moyenne | `sshd -T` : `passwordauthentication yes` | avec des clés seulement, l'essai de mots de passe ne mène à rien |
| `ssh_x11` | info | `sshd -T` : `x11forwarding yes` | inutile sur un serveur, surface en plus |
| `fail2ban` | moyenne | `fail2ban-client ping` | sans lui, les robots essaient indéfiniment SSH et les pages web |
| `remoteip` | moyenne | `RemoteIPHeader` sans `RemoteIPTrustedProxy` | même conséquence que `entetes_ip` : IP client falsifiable |
| `mysql_ecoute` | moyenne | `ss` : MariaDB à l'écoute sur toutes les interfaces | Jeedom n'utilise la base qu'en local |
| `zwavejs_ui` | moyenne | `ss` : port 8091 à l'écoute sur toutes les interfaces | l'interface Z-Wave JS UI permet d'exclure ou de réinitialiser tout le réseau Z-Wave |
| `ports_ouverts` | moyenne | `ss -tlnp` : ports à l'écoute sur toutes les interfaces, hors « Ports acceptés » (numéro ou nom de processus) | un service sans mot de passe ouvert au réseau local est à la merci de n'importe quel appareil infecté de la maison. Le nom de processus sert aux services dont le port change (Homebridge) |
| `api_refus` | moyenne | « Error code 2 » dans les 20 derniers Ko du log `api` | un client refusé en boucle est soit une appli à vous mal configurée, soit quelqu'un qui essaie des clés |
| `mqtt_anonyme` | haute | `allow_anonymous true` dans mosquitto ou le plugin MQTT Manager | tout client anonyme peut piloter les modules Zigbee et Z-Wave |
| `sudo_www` | info | `sudo -l` de www-data : NOPASSWD ALL | standard Jeedom, mais explique pourquoi la 2FA et l'API restreinte comptent autant |
| `box_ports` | info | case « Redirections de la box vérifiées » | le plugin ne voit pas la box : seul un rappel est possible |
| CVE | selon la NVD | version du core inférieure à la version corrigée | faille publique, exploitable par des robots |

Les règles `config` et `shell` sont dans `data/checks.json`, lisible et modifiable sans toucher au PHP.

## 5. La base des failles connues

Chaque nuit, et par le bouton « Mettre à jour la base », le plugin interroge la NVD (base publique du NIST) sur le mot « jeedom ». Chaque CVE qui vise `jeedom:jeedom` avec une version maximale devient une règle `core_version`, avec la gravité CVSS traduite (CRITICAL en critique, HIGH en haute, MEDIUM en moyenne, LOW en info). Le résultat est écrit dans `data/checks_remote.json`.

Une base complémentaire facultative (URL en `https://` dans la configuration) peut ajouter ses propres règles, au même format que `checks.json`.

**Garde-fou.** Un fichier téléchargé peut être piégé (serveur compromis, URL détournée). Il est donc filtré à chaque lecture, pas seulement au téléchargement :

- il ne peut **jamais** apporter de commande shell ni de correctif : ce serait l'exécution de code à distance sur votre machine en root ;
- sur une règle locale, il peut seulement **aggraver** la gravité : jamais l'adoucir (il ferait taire l'audit), jamais réécrire titre ou résolution (une résolution piégée serait suivie à la lettre par l'utilisateur) ;
- une règle nouvelle n'est acceptée que complète, de type `config` (clé, opérateur connu, valeur) ou `core_version` (version maximale) ;
- le HTML est retiré des textes, et un lien qui ne commence pas par `https://` est supprimé (pas de `javascript:`) ;
- un champ qui n'est pas du texte (tableau…) fait ignorer la règle, sinon PHP 8 ferait planter toute la liste.

Ce garde-fou est le premier point vérifié par le test (chapitre 14).

Limite : seule la borne haute des versions est lue. Une vieille faille peut donc être signalée à tort sur une branche ancienne encore maintenue.

## 6. Les correctifs

Le bouton « Corriger » n'existe que pour deux règles, avec un correctif écrit dans le plugin. Il est lu **uniquement dans la base locale** : la base téléchargée ne peut pas en ajouter. Une confirmation est toujours demandée, avec un avertissement propre à la règle.

| Correctif | Ce qu'il fait | Pourquoi ces précautions |
|---|---|---|
| `api_whiteip` | passe **l'API de la règle cliquée** en « IP blanche » | seulement celle-là, car l'avertissement affiché ne parlait que d'elle. Refusé si la liste blanche Jeedom ne couvre pas 127.0.0.1 : sinon les plugins locaux (Homebridge…) perdraient l'API. La vérification utilise `netMatch`, la fonction de Jeedom elle-même |
| `whiteips` | retire de la liste blanche Jeedom les entrées trop larges ou illisibles, garde les autres, ajoute 127.0.0.1 et votre sous-réseau local | même lecture que la règle `whiteips_large`, pour que le correctif retire exactement ce que la règle signale |

Avant chaque correctif, l'ancienne valeur est écrite dans `data/sauvegardes.json` (fichier verrouillé pendant l'écriture) **et** dans le log `secaudit`. Pourquoi les deux : le fichier est dans le dossier du plugin et disparaît s'il est réinstallé, le log reste. L'audit est relancé juste après pour montrer le résultat.

Les autres points touchent au système (SSH, MariaDB, Apache…) : une erreur pourrait couper l'accès à la machine. La résolution décrit la marche à suivre, à faire à la main.

## 7. Lire la liste blanche comme Jeedom la lit

La liste blanche de Jeedom (`security::whiteips`) est lue par sa fonction `netMatch`, qui a des comportements surprenants. Le plugin les reproduit pour ne pas dire « tout va bien » quand Jeedom comprend autre chose :

- une adresse dont un nombre commence par 0 (`192.168.1.01`) ou une plage mal écrite fait partir la plage de 0.0.0.0 : tout l'IPv4 est couvert ;
- un masque illisible, ou un saut de ligne après le masque, provoque une erreur PHP ;
- `127.*` ne couvre pas 127.0.0.1 pour `netMatch` (il faut `127.*.*.*` ou `127.0.0.0/8`) ;
- les espaces sont retirés mais pas les tabulations : une tabulation au milieu fausse la lecture ;
- en IPv6, `netMatch` ne sait pas lire un réseau : une étoile ou une plage couvre tout l'IPv6, un préfixe de plus de 32 bits provoque une erreur PHP. Seule une adresse IPv6 exacte est sûre.

C'est le rôle de la fonction `secaudit_tests::large()`, utilisée par la règle, par le correctif et par la vérification du correctif `api_whiteip`.

## 8. Tentatives d'intrusion

### Lecture du journal
Le plugin lit les 20 000 dernières lignes de `log/http.error`. Il y retient trois sortes de lignes : refus d'Apache (« client denied »), dossier non servi, script ou fichier absent. Pour chacune : date, IP, chemin, et si c'était un script PHP absent.

Le motif exige que `[client …]` suive directement les autres crochets de l'en-tête. Pourquoi : un attaquant peut écrire du texte dans la ligne (par le referer). Sans cette précaution, il fabriquerait un faux essai au nom d'une autre IP, par exemple la vôtre.

### Ce qu'elle cherchait
L'objectif est deviné d'après le chemin, premier motif reconnu : vol de secrets (`.env`, `wp-config`, `.git`, sauvegardes…), porte dérobée laissée par un autre pirate, pages de diagnostic, outils d'administration, CMS, équipements réseau, et enfin « appel Jeedom vers un script absent ».

- « Jeedom » vient en dernier et seulement pour un point d'entrée PHP de Jeedom, l'appli mobile ou une image, un style ou un script des dossiers Jeedom. Pourquoi : `/core/.env` ou `/plugins/x/data/base.db` sont des attaques, pas des appels Jeedom.
- Un chemin `/plugins/x/…` ne compte comme Jeedom que si le plugin x est installé ici. Sinon c'est un robot qui cherche un plugin vulnérable.
- Les chemins qu'aucun motif ne reconnaît sont listés à part sur la page, pour enrichir les familles.

### Historique sur 30 jours
Jeedom ramène `http.error` à quelques centaines de lignes : sans mémoire, un robot passé la veille aurait disparu. Les essais sont donc cumulés par IP dans `data/historique.json` : nombre, première et dernière fois, familles (comptées sur tous les essais), 20 chemins d'exemple de 200 caractères au plus.

- Un repère (« vu ») retient la date de la dernière ligne comptée : relire le journal toutes les heures ne compte jamais deux fois le même essai.
- Fichier verrouillé : la page et les crons (horaire et quotidien tournent ensemble à minuit) l'écrivent sans se marcher dessus.
- Limites : 30 jours, 500 IP, chemins tronqués. Pourquoi : les chemins sont choisis par l'attaquant et peuvent faire des Ko ; sans limite, un robot ferait grossir le fichier à volonté.
- Si l'encodage échoue (texte binaire), l'ancien fichier est gardé au lieu d'être vidé.

### Qui est derrière l'IP
`whois` donne le propriétaire et le pays ; un profil en est déduit : scanner d'une société de sécurité, VPN, serveur loué chez un hébergeur, connexion de particulier (machine sans doute infectée), « chez vous » (réseau privé, réservé ou Tailscale 100.64.0.0/10), ou « propriétaire non reconnu ».

- Le whois prend jusqu'à 10 s : il ne tourne **que dans le cron horaire**, 6 IP au plus par passage (les autres plugins attendent derrière le cron horaire). La page ne lit que le cache.
- Ordre : d'abord les IP bannies par Jeedom (leur pays décide de l'alerte), puis les IP bannies ou insistantes (3 essais au moins). Sautées : les IP des listes, et celles bannies seulement par sshd ou recidive sans essai web (le whois n'y change pas l'alerte et prendrait les places).
- Gardé 30 jours, 300 IP. Un whois muet est réessayé le lendemain seulement, sinon il bloquerait la file chaque heure.
- Pas de DNS inverse : il est lent, et son nom est choisi par le propriétaire de l'IP. Un robot nommé « shodan » se ferait passer pour un scanner inoffensif.
- Les réponses sont nettoyées de leur encodage (Latin-1, EUC-KR…) avant d'être gardées : sinon l'enregistrement échouerait et tout le cache serait perdu.

### Bannissements
Le plugin lit les bans de **toutes** les prisons fail2ban (`fail2ban-client`, par sudo) et ceux de Jeedom (cache `security::banip`). Jeedom ne purge ses bans expirés qu'à la connexion suivante : seuls les bans encore actifs sont gardés.

**Mémoire des bans vus (`bans_vus`).** Un ban Jeedom dure 10 minutes : levé avant le cron horaire, il passerait inaperçu, alors que c'est justement celui qui vous concerne (mots de passe ratés depuis l'appli). Les bans sont donc notés toutes les 5 minutes, avec la date de **première** vue, et gardés 30 heures.

- 30 heures et pas 24 : le rapport de 8 h tourne en même temps que le cron horaire et peut lire l'alerte de 7 h. Un ban vu à 7 h 10 doit encore y être le lendemain à 8 h.
- Date de première vue : un ban fail2ban de 8 heures, revu chaque heure, resterait sinon 38 heures dans la fenêtre, et l'alerte sortirait le surlendemain sans bouton Débannir.
- Un ban encore actif reste en mémoire au-delà de 30 heures (bans longs ou définitifs), sinon il serait purgé puis revu avec une nouvelle date.
- Si fail2ban ne répond plus, ses bans ne sont purgés qu'après 7 jours (on ne sait pas s'ils sont levés).

**Débannir.** IP validée avant tout appel shell, prison vérifiée parmi les prisons existantes, réponse de fail2ban contrôlée (sudo peut écrire un avertissement avant le nombre). Pour Jeedom, le compteur d'échecs de l'IP est aussi effacé : sinon un seul nouvel échec la rebannirait aussitôt. Le ban est retiré de la mémoire et l'alerte recalculée tout de suite (sinon le rapport de 8 h lirait l'alerte de 7 h qui nomme encore cette IP). Chaque débannissement est journalisé.
**Effacer l'alerte** : pour un ban déjà levé qui reste dans l'alerte ; fonctionne aussi quand fail2ban ne répond plus.

## 9. « Sans doute vous » et l'alerte

L'alerte du matin (`alerte_tentatives`, lue par le rapport de 8 h) ne parle que d'**une IP bannie qui est sans doute vous**. Pourquoi : des dizaines de robots sont bannis chaque jour, c'est le bruit de fond normal ; ce qui compte, c'est d'être prévenu quand c'est vous ou votre appli qui êtes à la porte.

Une IP est « sans doute vous » si :

- elle est dans votre liste blanche, ou sur votre réseau local ;
- ou c'est une connexion de particulier **française** qui n'a demandé que des scripts Jeedom absents (une appli ou un navigateur), ou que Jeedom a bannie pour mots de passe ratés sans aucun essai suspect.

Jamais : une IP de la liste noire, un hébergeur, un scanner, un VPN, un propriétaire non reconnu, ni une IP dont le whois n'est pas encore fait. Pourquoi : l'alerte propose de débannir, elle ne doit jamais le proposer pour un robot.

- Un ban sshd ou recidive seul ne compte que pour la liste blanche : votre téléphone ne fait pas de SSH, les robots si.
- Si l'IP a aussi cherché autre chose que Jeedom (`.env`, porte dérobée…), l'alerte le dit : à vérifier avant de débannir.
- L'alerte est datée de la première vue du ban et dit si le ban est déjà levé.

Limites assumées : un robot sur une box française qui ne tente que des mots de passe passerait pour vous (rare ; remède : liste noire). Vous depuis l'étranger, un VPN ou un opérateur inconnu ne seriez pas reconnu (remède : liste blanche).

## 10. Listes blanche et noire du plugin

Elles ne bannissent ni ne débannissent rien : elles décident seulement qui est « sans doute vous ». Ce ne sont pas les listes de Jeedom.

- **Format** : une IP ou un réseau CIDR par ligne, IPv4 ou IPv6, `#` pour un commentaire. Le plugin a sa propre lecture des réseaux (`couvre`, à partir de `inet_pton`) : il n'utilise pas `netMatch` et ses pièges (chapitre 7).
- **Liste blanche limitée à un /24 (IPv4) ou un /48 (IPv6)**. Pourquoi : un /48 est ce qu'un opérateur donne à un abonné ; au-delà, vous mettriez tout un opérateur en liste blanche et ses robots passeraient pour vous. Une entrée trop large saisie avant la 0.12 est ignorée et signalée sur la page.
- **Liste noire sans limite** : plus large = plus prudent.
- **Une IP dans les deux listes est traitée comme noire.**
- **Conflits refusés à l'enregistrement** : une entrée noire ajoutée ne doit couvrir ni l'adresse d'où vous enregistrez, ni une entrée de votre liste blanche (elle couperait l'alerte qui vous concerne). Une entrée blanche ajoutée ne doit pas être couverte par la liste noire.
- **Seules les entrées ajoutées sont vérifiées.** Pourquoi : une ancienne entrée (saisie avant une règle, ou votre IP 4G de la semaine dernière qui couvre maintenant autre chose) bloquerait sinon tout nouvel ajout.
- La vérification passe par `preConfig_liste_blanche` et `preConfig_liste_noire`, que Jeedom appelle à chaque enregistrement : une liste illisible est refusée avec un message au lieu d'être ignorée en silence.

## 11. Apprentissage et règle `chemins_vises`

Le journal d'erreurs ne contient que les échecs. **Une tentative réussie n'y apparaît pas** : si un robot demande `/data/sauvegarde.txt` et que le fichier existe, Apache le sert sans rien écrire dans `http.error`. D'où l'apprentissage :

1. Chaque heure, les chemins demandés par l'extérieur (hors réseau local et hors appels Jeedom) sont retenus : 1000 au plus, les plus récents.
2. À l'audit, ceux qui existent ici sont demandés en local à Apache (`curl` sur 127.0.0.1). Une réponse 200 veut dire que n'importe qui peut le lire.
3. Les scripts exécutables par PHP (.php, .phtml, .phar…) ne sont **jamais demandés** : la requête les exécuterait. Les chemins contenant `..` sont sautés.

**Porte dérobée.** Un script PHP absent quand un robot l'a demandé, puis présent ensuite, est signalé : c'est la trace typique d'un pirate qui a réussi à déposer son fichier et qui revient l'utiliser. Le fichier est vérifié par sa simple présence, jamais exécuté. Il est excusé s'il a été livré normalement :

- plugin : contenu plus ancien que la demande (le market garde la date de l'archive) ;
- core (dossiers `core/`, `desktop/`, `mobile/`, `3rdparty/`, `vendor/`, `install/`, jamais `data/` ni la racine) : même date de modification que `core/config/version` à 10 minutes près, mise à jour faite après la demande.

La date de changement (ctime) ne sert pas : Jeedom refait les droits de tous les fichiers à chaque mise à jour, elle serait la même partout. Ces scripts sont oubliés après 90 jours, pour qu'une fausse alerte finisse par s'effacer.

Limites : un intrus qui antidate son fichier passe ; un script publié par un plugin après la demande est signalé à tort (à vérifier) ; un fichier réservé au réseau local compte comme servi, puisque la requête vient de 127.0.0.1. Apache n'écrit les fichiers absents (hors PHP) qu'en `LogLevel info` ; au niveau `warn` par défaut, seuls les refus et les scripts PHP absents sont dans le journal.

## 12. Équipement, widget, assistant

**Commandes** : `score`, `problemes` (sans les points « info »), `resume`, `graves` (titres des problèmes critiques et hauts) et l'action `lancer`. Elles servent dans les scénarios et le rapport du matin.

**Widget** : affiché dans l'objet choisi en configuration (« Nulle part » ou un objet supprimé le masque). L'équipement n'est déplacé que si le choix change : un placement fait à la main reste. Le bouton « Voir l'audit » n'est ajouté que sur le dashboard, pas dans les designs. Le widget montre vos failles : à mettre dans un objet que seuls les admins voient.

**Lancer depuis le widget ou l'API** : refusé à un compte non admin, qu'il passe par le navigateur ou par l'API avec sa clé utilisateur. Pourquoi : l'audit lance des commandes en sudo pendant une minute. Un scénario ou un cron n'a pas d'utilisateur et passe. Limite : JeedomConnect ne transmet pas l'utilisateur, l'appli peut donc le lancer.

**Assistant** : à la première visite après l'installation (ou la mise à jour 0.19), cinq questions qui remplissent la configuration (widget, liste blanche, ports acceptés, box vérifiée, premier audit). Prérempli avec les réglages actuels : le rejouer ne perd rien. La liste blanche est enregistrée en premier : si elle est refusée, rien d'autre n'est changé. Les ports cochés sont ajoutés à « Ports acceptés », jamais retirés. Pourquoi un assistant : sans liste blanche ni ports acceptés, le premier rapport est plein de faux problèmes et l'alerte « sans doute vous » ne vous reconnaît pas en 4G.

## 13. Données gardées

| Donnée | Où | Durée, taille | Pourquoi |
|---|---|---|---|
| Rapport de l'audit | config `rapport` | dernier audit | page, commandes, comparaison pour les messages |
| Résumé et alerte | config `tentatives` | recalculés chaque heure | clé à part : le rapport du matin lit l'alerte sans relancer l'audit |
| Essais par IP | `data/historique.json` | 30 jours, 500 IP | le journal de Jeedom ne garde que quelques centaines de lignes |
| Whois | config `whois` | 30 jours (1 jour si muet), 300 IP | whois lent : jamais à l'affichage |
| Bans vus | config `bans_vus` | 30 h (plus si actif, 7 jours si fail2ban muet) | alerte du matin, bans courts |
| Chemins appris | config `chemins_appris` | 1000 chemins | règle `chemins_vises` |
| Scripts absents | config `scripts_absents` | 90 jours | détection de porte dérobée |
| Sauvegardes des correctifs | `data/sauvegardes.json` et log `secaudit` | sans limite | revenir en arrière |
| Failles téléchargées | `data/checks_remote.json` | remplacé chaque nuit | règles CVE |

La désinstallation retire toutes ces clés de configuration. Les fichiers `data/` du plugin disparaissent avec lui.

## 14. Prérequis, test, limites

**Prérequis** : `sudo` sans mot de passe pour www-data (installation Jeedom standard), la commande `whois`, fail2ban pour la partie bannissements. Sans sudo, les règles concernées passent en « erreur » ou ne voient rien ; le reste fonctionne.

**Test** : `sudo -u www-data php tests/selftest.php` depuis le dossier du plugin (refusé en root : les fichiers créés appartiendraient à root et le cron ne pourrait plus les écrire). Il vérifie le garde-fou de la base distante, la lecture des bans, du journal et des listes, l'alerte, l'affichage de ce document, puis évalue chaque règle sans enregistrer de rapport. Il s'arrête au premier échec (`ECHEC : …`). Pourquoi pas `assert()` : il est désactivé en production.

**Limites connues** (reprises des commentaires `ponytail:` du code) :

- base NVD : seule la borne haute des versions est lue ;
- historique : repère à la seconde, une ligne écrite dans la même seconde qu'un passage peut être perdue ;
- bans vus : configuration lue puis réécrite sans verrou, au pire un relevé perdu et rattrapé 5 minutes plus tard ;
- « sans doute vous » : heuristique, corrigée par les listes ;
- `chemins_vises` : fichier antidaté, fichier réservé au local, niveau de log d'Apache ;
- `fichiers_publics` : racine de `data/` seulement (`data/custom` et `data/customTemplates` sont servis exprès) ;
- le plugin ne voit ni la box, ni l'hôte d'une VM, ni ce qui passe hors d'Apache.
