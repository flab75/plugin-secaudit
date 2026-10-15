<?php
try {
  require_once __DIR__ . '/../../../../core/php/core.inc.php';
  include_file('core', 'authentification', 'php');
  if (!isConnect('admin')) throw new Exception(__('401 - Accès non autorisé', __FILE__));
  require_once __DIR__ . '/../class/secaudit.class.php';
  ajax::init();

  if (init('action') == 'run') ajax::success(secaudit::run());
  if (init('action') == 'updateBase') ajax::success(secaudit_base::mettreAJour());
  if (init('action') == 'fix') ajax::success(secaudit_correctifs::corriger(init('id')));
  if (init('action') == 'assistant') ajax::success(secaudit::assistant(init('plus_tard') ? null : $_POST));
  if (init('action') == 'unban') ajax::success(secaudit_bans::debannir(init('source'), init('prison'), init('ip')));

  throw new Exception(__('Aucune méthode correspondante à', __FILE__) . ' : ' . init('action'));
} catch (Throwable $e) { // TypeError compris : sinon le JS reçoit du HTML et le bouton reste grisé
  ajax::error(displayException($e), $e->getCode());
}
