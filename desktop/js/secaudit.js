document.querySelectorAll('.secauditAction').forEach(function (b) {
  b.addEventListener('click', async function () {
    var d = b.dataset
    if (d.action == 'fix' && !confirm((d.avertissement ? d.avertissement + '\n\n' : '') + '{{Appliquer le correctif ? L\'ancienne valeur est sauvegardée dans plugins/secaudit/data/sauvegardes.json.}}')) return
    if (d.action == 'unban' && !confirm('{{Débannir %s ?}}'.replace('%s', d.ip))) return
    var f = new FormData()
    for (var k in d) f.append(k, d[k])
    f.append('jeedom_token', JEEDOM_AJAX_TOKEN)
    b.classList.add('disabled')
    var r = await (await fetch('plugins/secaudit/core/ajax/secaudit.ajax.php', {method: 'POST', body: f})).json()
    if (r.state != 'ok') return jeedomUtils.showAlert({message: r.result, level: 'danger'}), b.classList.remove('disabled')
    location.reload()
  })
})

// Assistant : « Enregistrer » envoie les réponses, « Plus tard » le ferme sans rien changer (il ne revient plus seul)
document.querySelectorAll('#secauditAssistantOk, #secauditAssistantNon').forEach(function (b) {
  b.addEventListener('click', async function () {
    var a = document.getElementById('secauditAssistant'), f = new FormData()
    f.append('action', 'assistant')
    f.append('jeedom_token', JEEDOM_AJAX_TOKEN)
    if (b.id == 'secauditAssistantOk') {
      a.querySelectorAll('[data-k]').forEach(function (e) { f.append(e.dataset.k, e.type == 'checkbox' ? (e.checked ? 1 : 0) : e.value) })
      f.append('ports', Array.from(a.querySelectorAll('[data-port]:checked')).map(function (e) { return e.dataset.port }).join(','))
    } else f.append('plus_tard', 1)
    b.classList.add('disabled')
    var r = await (await fetch('plugins/secaudit/core/ajax/secaudit.ajax.php', {method: 'POST', body: f})).json()
    if (r.state != 'ok') return jeedomUtils.showAlert({message: r.result, level: 'danger'}), b.classList.remove('disabled')
    location.reload()
  })
})

// Documentation complète (docs/fr_FR/methodes.md) dans une fenêtre
document.getElementById('secauditDoc').addEventListener('click', function () {
  var u = 'index.php?v=d&plugin=secaudit&modal=methodes', t = '{{Audit sécurité : méthodes et raisons}}'
  if (window.jeeDialog) jeeDialog.dialog({id: 'jee_modal', title: t, contentUrl: u})
  else $('#md_modal').dialog({title: t}).load(u).dialog('open') // Jeedom < 4.4
})

// Boutons de l'assistant (ici plutôt qu'en onclick : une CSP sans 'unsafe-inline' les bloquerait)
document.getElementById('secauditAssistantOuvrir').addEventListener('click', function () {
  document.getElementById('secauditAssistant').style.display = ''
})
document.querySelectorAll('#secauditMonIp').forEach(function (b) { // absent quand l'adresse est locale
  b.addEventListener('click', function () {
    var t = b.parentNode.querySelector('textarea')
    t.value = (t.value.trim() ? t.value.trim() + '\n' : '') + b.dataset.ip + '  # {{ajoutée par l\'assistant}}'
  })
})
