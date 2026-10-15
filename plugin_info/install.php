<?php
require_once __DIR__ . '/../../../core/php/core.inc.php';

function secaudit_install() {
  secaudit::creerEquipement();
  message::add('secaudit', __('Audit sécurité installé : ouvrez la page du plugin, un assistant vous pose quelques questions.', __FILE__));
}

function secaudit_update() {
  secaudit::creerEquipement();
  foreach (['historique', 'historique_vu'] as $k) config::remove($k, 'secaudit'); // passés dans data/historique.json en 0.6
}

function secaudit_remove() {
  foreach (['rapport', 'tentatives', 'whois', 'chemins_appris', 'historique', 'historique_vu', 'bans_vus', 'scripts_absents', 'liste_blanche', 'liste_noire', 'widget_objet', 'assistant'] as $k) config::remove($k, 'secaudit');
}
