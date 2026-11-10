<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/soc.php';

$root = soc_root();

if (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) === '/healthz') {
    $datasets = [];
    foreach (glob($root . '/data/*/schema.json') ?: [] as $schemaPath) {
        $name = basename(dirname($schemaPath));
        $datasets[$name] = [
            'train' => is_file($root . '/data/' . $name . '/train/events.jsonl'),
            'holdout' => is_file($root . '/data/' . $name . '/holdout/events.jsonl'),
        ];
    }
    if (is_file($root . '/schema.json')) {
        $packaged = json_decode((string) file_get_contents($root . '/schema.json'), true);
        $packagedName = strtolower((string) ($packaged['case_id'] ?? 'case'));
        $datasets[$packagedName] = [
            'train' => is_file($root . '/train/events.jsonl'),
            'holdout' => is_file($root . '/holdout/events.jsonl'),
        ];
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status' => $datasets ? 'ok' : 'empty',
        'harness_version' => SOC_HARNESS_VERSION,
        'datasets' => $datasets,
    ], JSON_PRETTY_PRINT);
    exit;
}
$cases = [];
foreach (glob($root . '/data/*/schema.json') ?: [] as $schemaPath) {
    $schema = json_decode((string) file_get_contents($schemaPath), true);
    if (is_array($schema)) {
        $cases[basename(dirname($schemaPath))] = $schema;
    }
}
if (is_file($root . '/schema.json')) {
    $schema = json_decode((string) file_get_contents($root . '/schema.json'), true);
    if (is_array($schema)) {
        $cases[strtolower((string) ($schema['case_id'] ?? 'case'))] = $schema;
    }
}

$case = (string) ($_GET['case'] ?? (array_key_first($cases) ?: ''));
if ($case === '' || !isset($cases[$case])) {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="id"><head><meta charset="utf-8"><title>SOC Lab Viewer</title>'
        . '<link rel="stylesheet" href="/assets/style.css"></head><body><main><h1>SOC Lab Viewer</h1>'
        . '<p>Tidak ada dataset. Jalankan <code>tools\soc.ps1 -Action build</code> lebih dulu.</p></main></body></html>';
    exit;
}

$schema = $cases[$case];
$caseDir = soc_case_dir($root, $case);
$split = ($_GET['split'] ?? 'train') === 'holdout' ? 'holdout' : 'train';
$eventsPath = $caseDir . '/' . $split . '/events.jsonl';
$events = is_file($eventsPath) ? soc_load_events($eventsPath) : [];
$counts = ['train' => 0, 'holdout' => 0];
foreach (['train', 'holdout'] as $s) {
    $p = $caseDir . '/' . $s . '/events.jsonl';
    if (is_file($p)) {
        $counts[$s] = count(soc_load_events($p));
    }
}

$account = trim((string) ($_GET['account'] ?? ''));
$type = trim((string) ($_GET['type'] ?? ''));
$q = trim((string) ($_GET['q'] ?? ''));
$id = trim((string) ($_GET['id'] ?? ''));
$limit = max(1, min(500, (int) ($_GET['limit'] ?? 100)));

if ($id !== '') {
    $events = array_values(array_filter($events, static fn (array $e): bool => ($e['event_id'] ?? '') === $id));
} else {
    $events = array_values(array_filter($events, static function (array $e) use ($account, $type, $q): bool {
        if ($account !== '' && stripos((string) ($e['account'] ?? ''), $account) === false) {
            return false;
        }
        if ($type !== '' && (string) ($e['event_type'] ?? '') !== $type) {
            return false;
        }
        if ($q !== '' && stripos(json_encode($e), $q) === false) {
            return false;
        }
        return true;
    }));
}
$totalFiltered = count($events);
$events = array_slice($events, 0, $limit);

function h(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$types = [];
foreach ($events as $e) {
    $types[(string) ($e['event_type'] ?? '')] = true;
}
ksort($types);

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOC Viewer — <?= h($case) ?></title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header class="top">
  <strong>SOC Lab Viewer</strong>
  <span class="meta"><?= h((string) $schema['case_name']) ?> · schema <?= h((string) $schema['schema_version']) ?> · unit <?= h((string) $schema['unit_of_evaluation']) ?></span>
</header>
<main>
  <section class="banner">
    <div><span class="k">Train</span> <?= (int) $counts['train'] ?> event</div>
    <div><span class="k">Holdout</span> <?= (int) $counts['holdout'] ?> event (tanpa label)</div>
    <div><span class="k">SHA-256 train</span> <code><?= h(substr(soc_sha256($caseDir . '/train/events.jsonl'), 0, 16)) ?>…</code></div>
  </section>

  <nav class="tabs">
    <a class="<?= $split === 'train' ? 'active' : '' ?>" href="?case=<?= h($case) ?>&split=train">Training</a>
    <a class="<?= $split === 'holdout' ? 'active' : '' ?>" href="?case=<?= h($case) ?>&split=holdout">Holdout</a>
  </nav>

  <form method="get" class="filters">
    <input type="hidden" name="case" value="<?= h($case) ?>">
    <input type="hidden" name="split" value="<?= h($split) ?>">
    <label>Akun <input name="account" value="<?= h($account) ?>" placeholder="nadia@kampus.test"></label>
    <label>Tipe <input name="type" value="<?= h($type) ?>" placeholder="api.object.read" list="types"></label>
    <datalist id="types">
      <?php foreach (array_keys($types) as $t): ?><option value="<?= h((string) $t) ?>"><?php endforeach; ?>
    </datalist>
    <label>Cari <input name="q" value="<?= h($q) ?>" placeholder="kata kunci"></label>
    <label>Batas <input name="limit" type="number" value="<?= (int) $limit ?>" min="1" max="500"></label>
    <button type="submit">Filter</button>
    <a class="reset" href="?case=<?= h($case) ?>&split=<?= h($split) ?>">Reset</a>
  </form>

  <p class="count"><?= (int) $totalFiltered ?> event cocok; menampilkan <?= count($events) ?>.</p>

  <table>
    <thead><tr><th>Waktu (UTC)</th><th>Source</th><th>Akun</th><th>Tipe</th><th>Hasil</th><th>Objek</th><th>Event ID</th></tr></thead>
    <tbody>
    <?php foreach ($events as $e): ?>
      <tr>
        <td class="mono"><?= h((string) $e['event_time_utc']) ?></td>
        <td><?= h((string) $e['source']) ?></td>
        <td><?= h((string) $e['account']) ?></td>
        <td><?= h((string) $e['event_type']) ?></td>
        <td class="outcome-<?= h((string) $e['outcome']) ?>"><?= h((string) $e['outcome']) ?></td>
        <td class="mono"><?= h((string) ($e['object_id'] ?? '—')) ?></td>
        <td><a class="mono" href="?case=<?= h($case) ?>&split=<?= h($split) ?>&id=<?= h((string) $e['event_id']) ?>"><?= h((string) $e['event_id']) ?></a></td>
      </tr>
    <?php endforeach; ?>
    <?php if ($events === []): ?><tr><td colspan="7">Tidak ada event yang cocok.</td></tr><?php endif; ?>
    </tbody>
  </table>

  <?php if ($id !== '' && $events !== []): $e = $events[0]; ?>
    <section class="detail">
      <h2>Event <?= h((string) $e['event_id']) ?></h2>
      <dl>
        <?php foreach ($e as $k => $v): ?>
          <dt><?= h((string) $k) ?></dt>
          <dd class="mono"><?= h(is_scalar($v) ? (string) $v : json_encode($v, JSON_UNESCAPED_SLASHES)) ?></dd>
        <?php endforeach; ?>
      </dl>
      <h3>Raw record</h3>
      <pre><?= h(json_encode($e, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre>
      <p class="hint">Gunakan event ID ini saat menghubungkan bukti, hipotesis, dan tiket eskalasi.</p>
    </section>
  <?php elseif ($id !== ''): ?>
    <p class="error">Event ID tidak ditemukan pada split ini.</p>
  <?php endif; ?>

  <section class="hintbox">
    <h2>Catatan</h2>
    <p>Holdout tidak menyertakan label. Evaluasi aturan pada holdout hanya dilakukan mentor
    dengan label privat. Semua waktu ditampilkan dalam UTC; <code>event_time</code> asli
    memuat offset zona sumber.</p>
  </section>
</main>
</body>
</html>
