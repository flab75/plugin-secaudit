<?php
if (!isConnect('admin')) throw new Exception('{{401 - Accès non autorisé}}');
$r = secaudit::rapport();
$couleur = ['critique' => 'danger', 'haute' => 'warning', 'moyenne' => 'info', 'info' => 'default'];
$etat = ['probleme' => '<i class="fas fa-times-circle" style="color:#d9534f"></i>', 'ok' => '<i class="fas fa-check-circle" style="color:#5cb85c"></i>', 'erreur' => '<i class="fas fa-question-circle"></i>'];
?>
<div class="row row-overflow">
  <div class="col-xs-12">
    <h3>{{Audit de sécurité}}
      <?php if ($r) echo ' — {{score}} <strong>' . $r['score'] . '/100</strong> <small>(' . $r['date'] . ($r['base'] ? ', {{base distante du}} ' . $r['base'] : '') . ')</small>'; ?>
    </h3>
    <a class="btn btn-success secauditAction" data-action="run"><i class="fas fa-play"></i> {{Lancer l'audit}}</a>
    <a class="btn btn-default secauditAction" data-action="updateBase"><i class="fas fa-sync"></i> {{Mettre à jour la base (failles connues)}}</a>
    <a class="btn btn-default" href="index.php?v=d&p=plugin&id=secaudit"><i class="fas fa-wrench"></i> {{Configuration}}</a>
    <a class="btn btn-default" id="secauditAssistantOuvrir"><i class="fas fa-magic"></i> {{Assistant}}</a>
    <a class="btn btn-default" id="secauditDoc"><i class="fas fa-book"></i> {{Documentation}}</a>
    <br/><br/>
    <?php // Assistant : ouvert seul à la première visite après l'installation ou la mise à jour 0.19 (clé « assistant » absente), puis par le bouton. Questions = réglages de la configuration
    $ports = secaudit_tests::portsOuverts();
    $ip = getClientIp(); ?>
    <div id="secauditAssistant" class="panel panel-primary"<?php if (config::byKey('assistant', 'secaudit', 0) == 1) echo ' style="display:none"'; ?>>
      <div class="panel-heading"><i class="fas fa-magic"></i> {{Assistant de préconfiguration}}</div>
      <div class="panel-body form-horizontal">
        <div class="form-group"><label class="col-md-4 control-label">{{1. Où afficher le widget (problèmes graves, score) ?}}</label>
          <div class="col-md-6"><select class="form-control" data-k="widget_objet"><option value="">{{Nulle part}}</option>
            <?php foreach (jeeObject::all() as $o) echo '<option value="' . $o->getId() . '"' . ($o->getId() == config::byKey('widget_objet', 'secaudit', '') ? ' selected' : '') . '>' . htmlspecialchars($o->getName()) . '</option>'; ?>
          </select><small>{{Il dit vos failles : choisir un objet que seuls les admins voient.}}</small></div></div>
        <div class="form-group"><label class="col-md-4 control-label">{{2. Vos adresses hors de chez vous (4G, bureau, VPN) ?}}</label>
          <div class="col-md-6"><textarea class="form-control" rows="3" data-k="liste_blanche" placeholder="203.0.113.7  # 4G"><?php echo htmlspecialchars(config::byKey('liste_blanche', 'secaudit', '')); ?></textarea>
            <small>{{Une par ligne. Si l'une est bannie, l'alerte vous le dira.}}</small>
            <?php if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { ?>
            <a class="btn btn-xs btn-default" id="secauditMonIp" data-ip="<?php echo htmlspecialchars($ip); ?>">{{Ajouter mon adresse actuelle}} (<?php echo htmlspecialchars($ip); ?>)</a>
            <?php } ?></div></div>
        <div class="form-group"><label class="col-md-4 control-label">{{3. Ces services ouverts au réseau sont-ils voulus et protégés par un mot de passe ?}}</label>
          <div class="col-md-6"><?php if (!$ports) echo '{{Aucun service inattendu.}}';
            foreach ($ports as $p => $procs) echo '<label class="checkbox-inline"><input type="checkbox" data-port="' . (int)$p . '"/> ' . htmlspecialchars(trim("$p " . implode('/', $procs))) . '</label> '; ?>
            <br/><small>{{Cochés : plus signalés. Les autres restent dans l'audit.}}</small></div></div>
        <div class="form-group"><label class="col-md-4 control-label">{{4. Avez-vous vérifié les redirections de ports de votre box ?}}</label>
          <div class="col-md-6"><label class="checkbox-inline"><input type="checkbox" data-k="box_ok"<?php if (config::byKey('box_ok', 'secaudit', 0) == 1) echo ' checked'; ?>/> {{Oui : seul le 443 (et le 80) va vers Jeedom}}</label></div></div>
        <div class="form-group"><label class="col-md-4 control-label">{{5. Lancer le premier audit maintenant (environ 1 min) ?}}</label>
          <div class="col-md-6"><label class="checkbox-inline"><input type="checkbox" data-k="lancer" checked/> {{Oui}}</label></div></div>
        <div class="col-md-offset-4 col-md-6">
          <a class="btn btn-success" id="secauditAssistantOk"><i class="fas fa-check"></i> {{Enregistrer}}</a>
          <a class="btn btn-default" id="secauditAssistantNon">{{Plus tard}}</a>
          <small>{{Tout reste modifiable dans Configuration.}}</small></div>
      </div>
    </div>
    <?php if (!$r) { echo '<div class="alert alert-info">{{Aucun audit pour l\'instant.}}</div>'; } else { ?>
    <table class="table table-condensed table-bordered">
      <thead><tr><th></th><th>{{Gravité}}</th><th>{{Point}}</th><th>{{Constat}}</th><th>{{Comment résoudre}}</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($r['resultats'] as $x) { ?>
        <tr<?php if ($x['etat'] == 'ok') echo ' style="opacity:.55"'; ?>>
          <td><?php echo $etat[$x['etat']]; ?></td>
          <td><span class="label label-<?php echo $couleur[$x['gravite']]; ?>"><?php echo __($x['gravite'], 'plugins/secaudit/core/class/secaudit.class.php'); ?></span></td>
          <td><?php echo htmlspecialchars($x['titre']); ?></td>
          <td><?php echo htmlspecialchars($x['detail']); ?></td>
          <td><?php echo htmlspecialchars($x['resolution']);
            if ($x['reference']) echo ' <a href="' . htmlspecialchars($x['reference']) . '" target="_blank" rel="noopener">{{référence}}</a>'; ?></td>
          <td><?php if ($x['fix'] && $x['etat'] == 'probleme') echo '<a class="btn btn-xs btn-warning secauditAction" data-action="fix" data-id="' . htmlspecialchars($x['id']) . '" data-avertissement="' . htmlspecialchars($x['avertissement'] ?? '') . '">{{Corriger}}</a>'; ?></td>
        </tr>
      <?php } ?>
      </tbody>
    </table>
    <?php } ?>

    <h3>{{Tentatives d'intrusion et bannissements}}</h3>
    <?php $h = 'htmlspecialchars';
    try { $b = secaudit_tentatives::analyser(); }
    catch (Throwable $e) { echo '<div class="alert alert-danger">{{Analyse impossible}} : ' . $h($e->getMessage()) . '</div>'; $b = null; }
    if ($b) { ?>
    <?php if ($b['alerte']) echo '<div class="alert alert-danger">' . $h($b['alerte']) . '</div>';
    if ($i = secaudit_listes::ignorees()) echo '<div class="alert alert-warning">{{Entrées ignorées de votre liste blanche (plus larges qu\'un /24 ou un /48), à remplacer dans la configuration}} : ' . $h(implode(', ', $i)) . '</div>'; ?>
    <div class="alert alert-info" style="white-space:pre-line"><?php echo $h($b['resume']); ?></div>
    <p>{{Votre IP}} : <strong><?php echo $h($b['mon_ip']); ?></strong> — {{jamais bannies par fail2ban}} : <?php echo $h($b['ignore'] ?: '?'); ?></p>
    <table class="table table-condensed table-bordered">
      <thead><tr><th>{{IP}}</th><th>{{Qui}}</th><th>{{Ce qu'elle cherchait}}</th><th>{{Essais}}</th><th>{{Bannie jusqu'à}}</th><th></th></tr></thead>
      <tbody>
      <?php
      if (!$b['lignes']) echo '<tr><td colspan="6">{{Aucune tentative ni IP bannie.}}</td></tr>';
      foreach ($b['lignes'] as $x) { ?>
        <tr<?php if ($x['ip'] == $b['mon_ip'] || ($x['bans_recents'] && secaudit_resume::estVous($x))) echo ' class="danger"'; ?>>
          <td><?php echo $h($x['ip']); if ($x['liste']) echo ' <span class="label label-' . ($x['liste'] == 'noire' ? 'default">{{liste noire}}' : 'success">{{liste blanche}}') . '</span>'; ?></td>
          <td><?php echo $h(trim($x['qui']['org'] . ($x['qui']['pays'] ? ' (' . $x['qui']['pays'] . ')' : ''))); ?><br/><small><?php echo $h(__($x['qui']['profil'], 'plugins/secaudit/core/class/secaudit_whois.class.php')); // profil gardé en français (comparé), traduit ici ?></small></td>
          <td><?php echo $h(implode(' ; ', array_map('secaudit_journal::texte', $x['familles']))); ?>
            <br/><small><code><?php echo $h(implode('  ', $x['exemples'])); ?></code></small></td>
          <td><?php echo $x['nb']; ?><br/><small><?php echo $h($x['dernier']); ?></small></td>
          <td><?php foreach ($x['bans'] as $ban) echo $h($ban['fin'] . ' (' . $ban['source'] . ($ban['prison'] ? ' / ' . $ban['prison'] : '') . ')') . '<br/>'; ?></td>
          <td><?php foreach ($x['bans'] as $ban) { ?><a class="btn btn-xs btn-warning secauditAction" data-action="unban" data-source="<?php echo $h($ban['source']); ?>" data-prison="<?php echo $h($ban['prison']); ?>" data-ip="<?php echo $h($x['ip']); ?>">{{Débannir}}</a> <?php }
            // ban déjà levé mais encore dans l'alerte : Débannir ne trouve rien à lever, efface le ban vu et recalcule l'alerte
            if (secaudit_resume::estVous($x)) foreach (array_diff($x['bans_recents'], array_map(fn($ban) => $ban['prison'] ?: $ban['source'], $x['bans'])) as $k) { ?><a class="btn btn-xs btn-default secauditAction" data-action="unban" data-source="<?php echo $k == 'jeedom' ? 'jeedom' : 'fail2ban'; ?>" data-prison="<?php echo $k == 'jeedom' ? '' : $h($k); ?>" data-ip="<?php echo $h($x['ip']); ?>" title="{{Ban déjà levé}} (<?php echo $h($k); ?>)">{{Effacer l'alerte}}</a> <?php } ?></td>
        </tr>
      <?php } ?>
      </tbody>
    </table>
    <?php if ($b['non_classes']) { ?>
    <details><summary>{{Chemins visés non classés (à examiner pour enrichir l'analyse)}}</summary>
      <pre style="font-size:11px"><?php echo $h(implode("\n", $b['non_classes'])); ?></pre>
    </details>
    <?php } ?>
    <details><summary>{{Journal fail2ban (20 derniers bannissements / levées)}}</summary>
      <pre style="font-size:11px"><?php echo $h(implode("\n", $b['journal'])); ?></pre>
    </details>
    <?php } ?>
  </div>
</div>
<?php include_file('desktop', 'secaudit', 'js', 'secaudit'); ?>
