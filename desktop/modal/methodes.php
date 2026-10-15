<?php
if (!isConnect('admin')) throw new Exception('{{401 - Accès non autorisé}}');
require_once __DIR__ . '/../../core/class/secaudit.class.php';
echo '<div style="max-width:1100px">' . secaudit_doc::html() . '</div>';
