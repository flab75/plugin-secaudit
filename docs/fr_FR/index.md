# Audit sécurité

Audit quotidien de la sécurité de Jeedom et de sa machine. Le rapport donne un score sur 100 et, pour chaque point, le constat et la façon de le résoudre.

Comment chaque partie fonctionne et pourquoi : bouton **Documentation** de la page du plugin (`docs/fr_FR/methodes.md`).

## Utilisation
- **Assistant** : il pose 5 questions à la première ouverture de la page (voir « Assistant de préconfiguration »).
- Page du plugin : boutons **Lancer l'audit** et **Mettre à jour la base**. Le tableau est trié par gravité, avec les problèmes en tête.
- Chaque nuit (cronDaily), le plugin met la base à jour puis relance l'audit. Un nouveau problème de gravité haute ou critique crée un message Jeedom.
- Bouton **Configuration** : listes blanche et noire, ports acceptés, base complémentaire, widget.
- L'équipement « Audit sécurité » a 5 commandes : `score`, `problemes` (sans compter les points « info »), `resume` (texte), `graves` (titres des problèmes critiques et hauts, ou « Aucun problème grave ») et l'action `lancer`.
  Elles servent dans un scénario ou dans le rapport du matin.
- **Widget** : choisir l'objet dans la configuration (« Widget affiché dans ») ; il montre les problèmes graves, le score, le bouton Lancer (refusé à un compte non admin, depuis le navigateur ou l'API avec sa clé ; JeedomConnect ne transmet pas l'utilisateur, l'appli peut donc le lancer) et, sur le dashboard, le bouton « Voir l'audit » (page réservée aux admins). « Aucun », ou un objet supprimé, le masque. Le widget dit vos failles : le placer dans un objet que seuls les admins voient.

## Assistant de préconfiguration
Il s'ouvre seul en haut de la page du plugin à la première visite après l'installation, ou après la mise à jour vers la 0.19 (un message Jeedom le rappelle à l'installation). Il est prérempli avec les réglages actuels : le rejouer ne perd rien.

| # | Question | Ce que la réponse règle | Conseil |
|---|---|---|---|
| 1 | Où afficher le widget ? | `widget_objet` : l'équipement « Audit sécurité » est placé dans cet objet et rendu visible ; « Nulle part » le masque | Le widget montre vos failles : un objet que seuls les admins voient |
| 2 | Vos adresses hors de chez vous ? | Liste blanche (une IP ou un réseau par ligne, `#` pour un commentaire). Le bouton « Ajouter mon adresse actuelle » n'apparaît que si vous êtes connecté depuis l'extérieur | 4G, bureau, VPN : si l'une est bannie, l'alerte vous le dit. Au plus un /24 (IPv4) ou un /48 (IPv6) |
| 3 | Ces services ouverts au réseau sont-ils voulus et protégés par un mot de passe ? | Les ports cochés sont ajoutés à « Ports acceptés » (jamais retirés) et ne sont plus signalés | Ne cocher qu'un service qui demande un mot de passe. Les autres restent dans l'audit avec leur résolution |
| 4 | Avez-vous vérifié les redirections de ports de votre box ? | « Redirections de la box vérifiées » | Seul le 443 (et le 80 pour le certificat) doit aller vers Jeedom |
| 5 | Lancer le premier audit maintenant ? | Lance l'audit (environ 1 min) après l'enregistrement | |

- **Enregistrer** : la liste blanche est vérifiée en premier ; refusée (adresse illisible, réseau trop large, entrée de la liste noire), rien n'est enregistré et le message dit pourquoi.
- **Plus tard** : ferme l'assistant sans rien changer. Dans les deux cas il ne revient plus seul ; le bouton **Assistant** le rouvre.
- Non demandés (à régler dans Configuration) : liste noire, base de règles complémentaire.
- Si le premier audit échoue, les réponses sont déjà enregistrées : l'erreur s'affiche, recharger la page.

## Gravité et score
Le score part de 100. Chaque problème retire des points selon sa gravité :

| Gravité | Points retirés |
|---|---|
| critique | 25 |
| haute | 10 |
| moyenne | 4 |
| info | 0 |

## Règles
- `data/checks.json` est la base locale, livrée avec le plugin. Elle contient les tests de configuration, les tests shell, les tests intégrés, les failles connues et les correctifs.
- `data/checks_remote.json` est générée par « Mettre à jour la base ». Elle contient :
  - les CVE de la NVD (NIST) qui visent `jeedom:jeedom`. Chacune devient une règle « version du core ≤ X » ;
  - une base complémentaire facultative, à indiquer par URL dans la configuration du plugin.
- **Sécurité** : une base téléchargée peut seulement :
  - aggraver une règle existante (jamais l'adoucir, ni en changer le texte) ;
  - ajouter des règles complètes de type `config` (titre, clé, opérateur connu) ou `core_version` (titre, version max), HTML retiré.

  Elle ne peut jamais ajouter de commande shell ni de correctif.

## Correctifs
Le bouton **Corriger** apparaît seulement pour les correctifs écrits dans le plugin. Une confirmation est toujours demandée. L'ancienne valeur est sauvegardée dans `data/sauvegardes.json` et notée dans le log `secaudit` (le fichier disparaît si le plugin est réinstallé).

| Correctif | Effet |
|---|---|
| `api_whiteip` | L'API de la règle (HTTP, JSON-RPC ou TTS) passe en mode « IP blanche ». Refusé si aucune entrée de la liste blanche ne couvre 127.0.0.1 (127.0.0.1, 127.0.0.0/8, 127.*.*.* ; lu par `netMatch` de Jeedom, pour qui `127.*` ne couvre pas 127.0.0.1). |
| `whiteips` | Retire de la liste blanche les entrées plus larges qu'un /24 ou illisibles (`192.168.1.01-…`, tabulation au milieu : `netMatch` ferait partir la plage de 0.0.0.0) (et tout réseau IPv6 : `netMatch` de Jeedom prend une étoile ou une plage IPv6 pour tout l'IPv6, et plante sur un préfixe > 32), garde les autres, ajoute `127.0.0.1` et `<sous-réseau local>.*`. |

Les autres points (SSH, MariaDB, Z-Wave JS UI…) touchent au système : la résolution les décrit, à faire à la main.

## Tentatives d'intrusion et bannissements
Sous l'audit, un résumé en français puis une ligne par IP qui a sondé Jeedom (journal `log/http.error`) ou qui est bannie :
- **Qui** : propriétaire de l'IP (whois fait chaque heure par le cron, gardé 30 jours) et profil deviné : scanner d'une société de sécurité, serveur loué, VPN, particulier (machine infectée), chez vous, ou « non reconnu ».
- Les essais sont gardés 30 jours par IP (le journal de Jeedom ne garde que ~500 lignes).
- « Sans doute vous » : une IP de la liste blanche, ou une connexion de particulier française qui n'a demandé que des points d'entrée Jeedom absents (plugins installés seulement), ou que Jeedom a bannie pour mots de passe ratés sans essai suspect. Jamais une IP de la liste noire, un hébergeur, un scanner, un VPN, un propriétaire non reconnu ou tant que le whois n'est pas fait.
  Si elle a été bannie dans les 30 h (bans Jeedom notés toutes les 5 min, même levés depuis ; Débannir l'efface) : alerte en rouge, datée de la première vue du ban, recalculée chaque heure et après chaque Débannir et reprise dans le rapport du matin (`alerte_tentatives`). Un ban sshd ou recidive seul ne compte que pour la liste blanche.

## Listes blanche et noire
Dans la configuration du plugin, une IP ou un réseau par ligne (`203.0.113.7`, `203.0.113.0/24`, `2a01:db8::/48`), `#` pour un commentaire. Une adresse illisible est refusée à l'enregistrement. En liste blanche, un réseau plus large qu'un /24 (IPv4) ou un /48 (IPv6, un abonné) est refusé aussi ; saisi avant la 0.12, il est ignoré et signalé sur la page. La liste noire n'a pas de limite de largeur, mais une entrée ajoutée est refusée si elle couvre l'adresse d'où vous enregistrez ou une entrée de votre liste blanche (elle couperait l'alerte qui vous concerne) ; de même, une entrée blanche ajoutée et couverte par la liste noire est refusée. Les entrées déjà enregistrées ne sont pas revérifiées.
- **Liste blanche** : vos adresses hors de chez vous (4G, bureau, VPN). Si l'une est bannie, l'alerte le dit toujours, en précisant si elle a aussi cherché autre chose que Jeedom (à vérifier avant de débannir). Ce n'est pas la liste blanche de Jeedom : elle n'empêche pas le bannissement.
- **Liste noire** : des IP à ne jamais prendre pour vous, même depuis une box française. Elles ne sont pas bannies pour autant. Une IP dans les deux listes est traitée comme noire.

Sur la page, l'IP porte une étiquette « liste blanche » ou « liste noire ».
- Historique des essais par IP sur 30 jours : `data/historique.json`.
- **Ce qu'elle cherchait** : objectif deviné d'après les chemins demandés (vol de secrets, porte dérobée, pages de diagnostic, outils d'admin, CMS, équipements réseau, script Jeedom absent).
- Essais, fin du bannissement, bouton **Débannir** (journalisé dans le log `secaudit`). Ban déjà levé mais encore dans l'alerte : bouton **Effacer l'alerte** (marche aussi si fail2ban ne répond plus ; ses bans sont alors oubliés après 7 jours).
- Dans le résumé, une IP de la liste blanche qui a cherché autre chose que Jeedom est comptée avec les adresses extérieures.
- Les chemins non classés sont listés à part : ce sont eux qui servent à enrichir les familles (`FAMILLES` dans la classe).

**Apprentissage** : chaque heure, les chemins visés par l'extérieur sont retenus (1000 au plus). La règle `chemins_vises` vérifie
que ceux qui existent ici ne sont pas servis (requête locale, en sautant .php, .phtml, .phar… que PHP exécuterait ; un fichier réservé au réseau local compte comme servi).
Elle signale aussi un script PHP absent quand un robot l'a demandé et présent maintenant (porte dérobée possible), vérifié sans l'exécuter ; sauf s'il a été livré : pour un plugin, contenu plus ancien que la demande (le market garde la date de l'archive) ; pour le core (ses dossiers `core/`, `desktop/`, `mobile/`, `3rdparty/`, `vendor/`, `install/` ; jamais `data/` ni la racine), même date de modification que `core/config/version` à 10 min près, mise à jour faite après la demande. La date de changement (ctime) ne sert pas : Jeedom refait les droits de tous les fichiers à chaque mise à jour. Ces scripts sont oubliés après 90 jours.
Le journal ne contient que les échecs : une tentative réussie n'y apparaîtrait pas, c'est le rôle de cette règle.
Limite : Apache n'écrit les fichiers absents (hors PHP) qu'en `LogLevel info` ; au niveau `warn` par défaut, seuls les refus et les scripts PHP absents sont dans `http.error`.

Nécessite `sudo` sans mot de passe pour www-data (installation Jeedom standard) et la commande `whois` (installée par les dépendances du plugin).

## Données et confidentialité
Le plugin ne collecte rien pour son auteur et n'envoie aucune statistique.

**Ce qui sort de la machine :**
- Les **adresses IP publiques** qui ont sondé Jeedom ou ont été bannies, envoyées aux serveurs `whois` des registres d'adresses (RIPE, ARIN…) par le cron horaire, au plus une fois par IP tous les 30 jours. Une IP de votre liste blanche qui apparaît dans le journal est envoyée aussi ; les adresses locales et Tailscale jamais.
- Une requête à la **NVD** (NIST, `services.nvd.nist.gov`) chaque nuit, avec le seul mot-clé `jeedom`.
- Une requête à la **base complémentaire**, seulement si vous en indiquez l'URL. Son serveur voit l'adresse IP publique de votre box.

**Ce qui est gardé sur la machine :**

| Donnée | Où | Durée |
|---|---|---|
| Essais par IP (date, chemins demandés) | `data/historique.json` | 30 jours après le dernier essai |
| Propriétaire de chaque IP (whois) | configuration du plugin | 30 jours, 300 IP au plus |
| Bans vus | configuration du plugin | 30 heures (7 jours si fail2ban ne répond plus) |
| Chemins visés par les robots (sans IP) | configuration du plugin | 1000 chemins au plus ; scripts absents : 90 jours |
| Anciennes valeurs avant un correctif (liste blanche Jeedom…) | `data/sauvegardes.json` et log `secaudit` | jusqu'à réinstallation / rotation des logs |
| Rapport, listes blanche et noire | configuration du plugin | jusqu'à la désinstallation |

La désinstallation efface la configuration du plugin ; ses fichiers `data/` partent avec son dossier.

## Plateforme
La première ligne du rapport indique sur quoi tourne Jeedom (VM, Raspberry Pi, Docker ou machine physique), avec l'OS et les versions. Sur une VM, la sécurité dépend aussi de l'hôte, que le plugin ne voit pas.

## Test
`sudo -u www-data php tests/selftest.php` (refusé en root) lance un essai à blanc depuis le dossier du plugin ; ajouter `en_US` pour avoir les textes générés en anglais. Il vérifie le garde-fou de la base distante, la lecture du journal et l'alerte, puis évalue chaque règle sans enregistrer de rapport. Il met à jour l'historique, les bans vus et les chemins appris, comme le cron.
