<?php
require_once __DIR__ . '/../../../core/php/core.inc.php';
include_file('core', 'authentification', 'php');
if (!isConnect('admin')) {
  include_file('desktop', '404', 'php');
  die();
}
?>
<form class="form-horizontal">
  <fieldset>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Base de règles complémentaire (URL JSON)}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Facultatif. Même format que data/checks.json. Seuls les tests de configuration et de version y sont acceptés, jamais de commande ni de correctif.}}"></i></sup>
      </label>
      <div class="col-md-6"><input class="configKey form-control" data-l1key="checks_url" placeholder="https://..."/></div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Ports acceptés}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Ports ouverts à tout le réseau qui ne sont pas signalés (numéros de port ou noms de processus, séparés par des virgules). Vide = 22,80,443,1883,8883,3306,8091.}}"></i></sup>
      </label>
      <div class="col-md-6"><input class="configKey form-control" data-l1key="ports_ok" placeholder="22,80,443,1883,8883,3306,8091"/></div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Redirections de la box vérifiées}}</label>
      <div class="col-md-6"><input type="checkbox" class="configKey" data-l1key="box_ok"/></div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Liste blanche (vos adresses)}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Une IP ou un réseau par ligne (1.2.3.4, 1.2.3.0/24, 2a01:db8::/48), # pour un commentaire. Vos adresses hors de chez vous (4G, bureau, résidence secondaire) : si l'une est bannie, l'alerte le signale toujours. Ne la protège pas du bannissement (voir la liste blanche de Jeedom).}}"></i></sup>
      </label>
      <div class="col-md-6"><textarea class="configKey form-control" data-l1key="liste_blanche" rows="4" placeholder="203.0.113.7  # 4G"></textarea></div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Liste noire}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Même format. Ces IP ne sont jamais prises pour vous, même depuis une box française, et ne déclenchent pas l'alerte. Elles ne sont pas bannies pour autant. Une IP dans les deux listes est traitée comme noire.}}"></i></sup>
      </label>
      <div class="col-md-6"><textarea class="configKey form-control" data-l1key="liste_noire" rows="4" placeholder="198.51.100.0/24"></textarea></div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Widget (problèmes graves) affiché dans}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Objet où afficher le widget de l'équipement « Audit sécurité » : problèmes critiques et hauts, score, bouton Lancer. Aucun = masqué.}}"></i></sup>
      </label>
      <div class="col-md-6"><select class="configKey form-control" data-l1key="widget_objet">
        <option value="">{{Aucun (masqué)}}</option>
        <?php foreach (jeeObject::all() as $o) echo '<option value="' . $o->getId() . '">' . htmlspecialchars($o->getName()) . '</option>'; ?>
      </select></div>
    </div>
  </fieldset>
</form>
