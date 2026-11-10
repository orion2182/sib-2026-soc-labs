<?php
declare(strict_types=1);

/**
 * Deterministic SOC-2 (suspicious endpoint execution) generator.
 * No randomness; inert event records only. Usage: php shared/bin/generate-soc2.php
 */

require_once dirname(__DIR__) . '/lib/soc.php';

$root = soc_root();
$sensors = ['endpoint' => 'edr-win-1', 'inventory' => 'cmdb-1', 'maintenance' => 'change-cal-1'];
$counter = [];

function s2_event(
    string $prefix,
    string $source,
    string $time,
    array $fields,
    string $label,
    ?string $seqId,
    array &$events,
    array &$labels,
    array &$seqEvents,
    array &$counter,
    array $sensors
): string {
    $counter[$prefix] = ($counter[$prefix] ?? 0) + 1;
    $id = sprintf('%s-%04d', $prefix, $counter[$prefix]);
    $utc = (new DateTimeImmutable($time))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    $event = array_merge([
        'event_id' => $id,
        'case_id' => 'SOC-2',
        'schema_version' => '1.0.0',
        'source' => $source,
        'event_time' => $time,
        'event_time_utc' => $utc,
        'sensor' => $sensors[$source],
        'host' => '',
        'account' => '',
        'event_type' => '',
        'outcome' => 'success',
        'note' => '',
    ], $fields);
    $events[] = $event;
    $labels['event_labels'][$id] = $label;
    if ($seqId !== null) {
        $seqEvents[$seqId][] = $id;
    }
    return $id;
}

function build_soc2(string $prefix, string $day, array &$events, array &$labels, array &$seqEvents, array $sensors): void
{
    $counter = [];
    $add = static function (string $source, string $time, array $fields, string $label, ?string $seqId = null)
        use (&$events, &$labels, &$seqEvents, &$counter, $sensors, $prefix): string {
        return s2_event($prefix, $source, $time, $fields, $label, $seqId, $events, $labels, $seqEvents, $counter, $sensors);
    };
    $T = $day . 'T';

    // Inventory context.
    foreach ([
        ['WS-0142', 'aurel@kampus.test', 'staff workstation', 'Finance'],
        ['WS-0207', 'bima@kampus.test', 'staff workstation', 'Registrar'],
        ['WS-0231', 'rendra@kampus.test', 'staff workstation', 'Student Affairs'],
        ['WS-0301', 'shared-kiosk', 'kiosk', 'Library'],
    ] as [$host, $account, $role, $unit]) {
        $add('inventory', $T . '07:00:00+07:00', [
            'host' => $host, 'account' => $account, 'event_type' => 'host.info', 'outcome' => 'success',
            'role' => $role, 'note' => 'Host inventory entry (' . $unit . ').',
        ], 'benign');
    }
    $add('maintenance', $T . '07:05:00+07:00', [
        'host' => 'WS-0207', 'account' => 'change-cal', 'event_type' => 'maintenance.window', 'outcome' => 'allowed',
        'maintenance_id' => 'MNT-2026-11-05-A', 'note' => 'Approved helpdesk deployment 09:30-11:30.',
    ], 'benign');
    $add('maintenance', $T . '07:06:00+07:00', [
        'host' => 'WS-0142', 'account' => 'change-cal', 'event_type' => 'maintenance.window', 'outcome' => 'allowed',
        'maintenance_id' => 'MNT-2026-11-05-B', 'note' => 'Approved software deployment 10:30-12:00.',
    ], 'benign');

    // Ordinary user activity.
    $add('endpoint', $T . '08:55:00+07:00', [
        'host' => 'WS-0142', 'account' => 'aurel@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 1000, 'process_guid' => 'P-1000', 'parent_guid' => 'P-0001', 'process_name' => 'explorer.exe',
        'parent_name' => 'userinit.exe', 'command_line' => 'C:\\Windows\\explorer.exe', 'signer' => 'Microsoft',
        'note' => 'Normal shell.',
    ], 'benign');
    $add('endpoint', $T . '08:56:00+07:00', [
        'host' => 'WS-0142', 'account' => 'aurel@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 1200, 'process_guid' => 'P-1200', 'parent_guid' => 'P-1000', 'process_name' => 'outlook.exe',
        'parent_name' => 'explorer.exe', 'command_line' => 'C:\\Program Files\\Office\\outlook.exe', 'signer' => 'Microsoft',
        'note' => 'Normal mail client.',
    ], 'benign');
    $add('endpoint', $T . '08:57:00+07:00', [
        'host' => 'WS-0207', 'account' => 'bima@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 2000, 'process_guid' => 'P-2000', 'parent_guid' => 'P-0002', 'process_name' => 'chrome.exe',
        'parent_name' => 'explorer.exe', 'command_line' => 'C:\\Program Files\\Google\\Chrome\\chrome.exe', 'signer' => 'Google',
        'note' => 'Normal browser.',
    ], 'benign');

    // Intended malicious chain.
    $base = new DateTimeImmutable($T . '09:00:00+07:00');
    $add('endpoint', $base->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 3000, 'process_guid' => 'P-3000', 'parent_guid' => 'P-0003', 'process_name' => 'explorer.exe',
        'parent_name' => 'userinit.exe', 'command_line' => 'C:\\Windows\\explorer.exe', 'signer' => 'Microsoft',
        'note' => 'Normal shell before the document is opened.',
    ], 'benign', 'SEQ-EPR-T1');
    $add('endpoint', $base->modify('+5 minutes')->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 3100, 'process_guid' => 'P-3100', 'parent_guid' => 'P-3000', 'process_name' => 'winword.exe',
        'parent_name' => 'explorer.exe', 'command_line' => 'C:\\Program Files\\Office\\winword.exe "Rekap.docx"',
        'signer' => 'Microsoft', 'note' => 'Document opened from an email attachment.',
    ], 'malicious', 'SEQ-EPR-T1');
    $add('endpoint', $base->modify('+5 minutes 30 seconds')->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 3110, 'process_guid' => 'P-3110', 'parent_guid' => 'P-3100', 'process_name' => 'powershell.exe',
        'parent_name' => 'winword.exe',
        'command_line' => 'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA',
        'signer' => '', 'note' => 'Encoded PowerShell spawned by the document.',
    ], 'malicious', 'SEQ-EPR-T1');
    $add('endpoint', $base->modify('+6 minutes')->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'script.block', 'outcome' => 'blocked',
        'pid' => 3110, 'process_guid' => 'P-3110', 'parent_guid' => 'P-3100', 'process_name' => 'powershell.exe',
        'file_path' => 'C:\\Users\\rendra\\AppData\\Local\\Temp\\a1.ps1', 'bytes' => 1840,
        'note' => 'Script block written to the user temp directory.',
    ], 'malicious', 'SEQ-EPR-T1');
    $add('endpoint', $base->modify('+6 minutes 30 seconds')->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'network.connect', 'outcome' => 'success',
        'pid' => 3110, 'process_guid' => 'P-3110', 'dest_ip' => '203.0.113.50', 'dest_port' => 443, 'bytes' => 9200,
        'note' => 'Outbound connection after the encoded command.',
    ], 'malicious', 'SEQ-EPR-T1');
    $add('endpoint', $base->modify('+7 minutes')->format('c'), [
        'host' => 'WS-0231', 'account' => 'rendra@kampus.test', 'event_type' => 'file.create', 'outcome' => 'success',
        'pid' => 3110, 'process_guid' => 'P-3110', 'file_path' => 'C:\\Users\\rendra\\AppData\\Local\\Temp\\stage.bin',
        'bytes' => 48210, 'note' => 'Staged file after the connection.',
    ], 'malicious', 'SEQ-EPR-T1');

    // Legitimate helpdesk deployment.
    $help = new DateTimeImmutable($T . '10:00:00+07:00');
    $add('endpoint', $help->format('c'), [
        'host' => 'WS-0207', 'account' => 'helpdesk@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 4000, 'process_guid' => 'P-4000', 'parent_guid' => 'P-0004', 'process_name' => 'ccmexec.exe',
        'parent_name' => 'services.exe', 'command_line' => 'C:\\Windows\\ccmexec.exe', 'signer' => 'Microsoft',
        'maintenance_id' => 'MNT-2026-11-05-A', 'note' => 'Configuration Manager agent.',
    ], 'benign', 'SEQ-HD-T1');
    $add('endpoint', $help->modify('+20 seconds')->format('c'), [
        'host' => 'WS-0207', 'account' => 'helpdesk@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 4010, 'process_guid' => 'P-4010', 'parent_guid' => 'P-4000', 'process_name' => 'powershell.exe',
        'parent_name' => 'ccmexec.exe', 'command_line' => 'powershell.exe -File C:\\IT\\Invoke-Helpdesk.ps1 -Ticket HD-4412',
        'signer' => 'IT-Approved', 'maintenance_id' => 'MNT-2026-11-05-A',
        'note' => 'Signed helpdesk script inside the approved window.',
    ], 'benign', 'SEQ-HD-T1');
    $add('endpoint', $help->modify('+40 seconds')->format('c'), [
        'host' => 'WS-0207', 'account' => 'helpdesk@kampus.test', 'event_type' => 'script.block', 'outcome' => 'blocked',
        'pid' => 4010, 'process_guid' => 'P-4010', 'file_path' => 'C:\\IT\\Invoke-Helpdesk.ps1', 'bytes' => 640,
        'maintenance_id' => 'MNT-2026-11-05-A', 'note' => 'Approved script content.',
    ], 'benign', 'SEQ-HD-T1');

    // Legitimate software deployment.
    $dep = new DateTimeImmutable($T . '11:00:00+07:00');
    $add('endpoint', $dep->format('c'), [
        'host' => 'WS-0142', 'account' => 'itdeploy@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 5000, 'process_guid' => 'P-5000', 'parent_guid' => 'P-0005', 'process_name' => 'ccmexec.exe',
        'parent_name' => 'services.exe', 'command_line' => 'C:\\Windows\\ccmexec.exe', 'signer' => 'Microsoft',
        'maintenance_id' => 'MNT-2026-11-05-B', 'note' => 'Deployment agent.',
    ], 'benign', 'SEQ-DEP-T1');
    $add('endpoint', $dep->modify('+20 seconds')->format('c'), [
        'host' => 'WS-0142', 'account' => 'itdeploy@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 5010, 'process_guid' => 'P-5010', 'parent_guid' => 'P-5000', 'process_name' => 'powershell.exe',
        'parent_name' => 'ccmexec.exe', 'command_line' => 'powershell.exe -File C:\\IT\\deploy.ps1 -Package CRM-9',
        'signer' => 'IT-Approved', 'maintenance_id' => 'MNT-2026-11-05-B', 'note' => 'Signed deployment script.',
    ], 'benign', 'SEQ-DEP-T1');
    $add('endpoint', $dep->modify('+40 seconds')->format('c'), [
        'host' => 'WS-0142', 'account' => 'itdeploy@kampus.test', 'event_type' => 'file.create', 'outcome' => 'success',
        'pid' => 5010, 'process_guid' => 'P-5010', 'file_path' => 'C:\\Program Files\\CRM\\crm.exe', 'bytes' => 120000,
        'maintenance_id' => 'MNT-2026-11-05-B', 'note' => 'Deployed application binary.',
    ], 'benign', 'SEQ-DEP-T1');

    // Bounded uncertainty: orphan process with no parent telemetry.
    $add('endpoint', $T . '12:00:00+07:00', [
        'host' => 'WS-0301', 'account' => 'shared-kiosk', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 6000, 'process_guid' => 'P-6000', 'parent_guid' => '', 'process_name' => 'powershell.exe',
        'parent_name' => '', 'command_line' => 'powershell.exe -nop -enc SQBFAFgA', 'signer' => '',
        'note' => 'No parent telemetry; the chain cannot be completed from this sensor alone.',
    ], 'benign', 'SEQ-ORP-T1');

    // PID reuse on a normal host.
    $add('endpoint', $T . '13:00:00+07:00', [
        'host' => 'WS-0142', 'account' => 'aurel@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 4412, 'process_guid' => 'P-7001', 'parent_guid' => 'P-1000', 'process_name' => 'notepad.exe',
        'parent_name' => 'explorer.exe', 'command_line' => 'notepad.exe', 'signer' => 'Microsoft',
        'note' => 'First use of pid 4412.',
    ], 'benign', 'SEQ-PID-T1');
    $add('endpoint', $T . '13:10:00+07:00', [
        'host' => 'WS-0142', 'account' => 'aurel@kampus.test', 'event_type' => 'process.create', 'outcome' => 'success',
        'pid' => 4412, 'process_guid' => 'P-7002', 'parent_guid' => 'P-1000', 'process_name' => 'calc.exe',
        'parent_name' => 'explorer.exe', 'command_line' => 'calc.exe', 'signer' => 'Microsoft',
        'note' => 'Second, unrelated process with the reused pid.',
    ], 'benign', 'SEQ-PID-T1');

    $labels['sequences'] = [
        ['sequence_id' => 'SEQ-EPR-T1', 'label' => 'malicious', 'title' => 'Document to encoded PowerShell to callback',
         'event_ids' => $seqEvents['SEQ-EPR-T1'] ?? [], 'explanation' => 'Winword spawns encoded PowerShell, writes a temp script, connects out, then stages a file.'],
        ['sequence_id' => 'SEQ-HD-T1', 'label' => 'benign', 'title' => 'Approved helpdesk script',
         'event_ids' => $seqEvents['SEQ-HD-T1'] ?? [], 'explanation' => 'Signed IT script from the deployment agent inside the maintenance window.'],
        ['sequence_id' => 'SEQ-DEP-T1', 'label' => 'benign', 'title' => 'Approved software deployment',
         'event_ids' => $seqEvents['SEQ-DEP-T1'] ?? [], 'explanation' => 'Signed deployment from the agent with a maintenance record.'],
        ['sequence_id' => 'SEQ-ORP-T1', 'label' => 'benign', 'title' => 'Orphan process with missing parent telemetry',
         'event_ids' => $seqEvents['SEQ-ORP-T1'] ?? [], 'explanation' => 'Suspicious shape but no network or parent evidence; not a confirmed chain.'],
        ['sequence_id' => 'SEQ-PID-T1', 'label' => 'benign', 'title' => 'PID reuse',
         'event_ids' => $seqEvents['SEQ-PID-T1'] ?? [], 'explanation' => 'Same pid, different process GUIDs and images.'],
    ];
}

$trainEvents = [];
$trainLabels = ['case_id' => 'SOC-2', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$trainSeq = [];
build_soc2('SOC2-T', '2026-11-05', $trainEvents, $trainLabels, $trainSeq, $sensors);

$holdoutEvents = [];
$holdoutLabels = ['case_id' => 'SOC-2', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$holdoutSeq = [];
build_soc2('SOC2-H', '2026-11-12', $holdoutEvents, $holdoutLabels, $holdoutSeq, $sensors);

// The holdout keeps the same mechanics but uses different hosts and a different
// destination so a rule cannot key on the training identifiers.
foreach ($holdoutEvents as &$event) {
    if (isset($event['host'])) {
        $event['host'] = str_replace('WS-0', 'WS-1', (string) $event['host']);
    }
    if (($event['dest_ip'] ?? '') === '203.0.113.50') {
        $event['dest_ip'] = '198.51.100.60';
    }
}
unset($event);

soc_write_events($root . '/data/soc-2/train/events.jsonl', $trainEvents);
soc_json_write($root . '/data/soc-2/train/labels.json', $trainLabels);
soc_write_events($root . '/data/soc-2/holdout/events.jsonl', $holdoutEvents);
soc_json_write($root . '/instructor-private/soc-2/holdout_labels.json', $holdoutLabels);
soc_json_write($root . '/instructor-private/soc-2/generation.json', [
    'case_id' => 'SOC-2',
    'schema_version' => '1.0.0',
    'generator' => 'shared/bin/generate-soc2.php',
    'seed' => 'fixed-construction-no-rng',
    'harness_version' => SOC_HARNESS_VERSION,
    'train_events' => count($trainEvents),
    'holdout_events' => count($holdoutEvents),
    'train_malicious' => count(array_filter($trainLabels['event_labels'], static fn ($l) => $l === 'malicious')),
    'holdout_malicious' => count(array_filter($holdoutLabels['event_labels'], static fn ($l) => $l === 'malicious')),
]);

printf("SOC-2 generated: train=%d events, holdout=%d events\n", count($trainEvents), count($holdoutEvents));
