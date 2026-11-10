<?php
declare(strict_types=1);

/**
 * Deterministic SOC-1 (API account takeover) dataset generator.
 *
 * No randomness is used, so repeated runs are byte-identical. All identities,
 * addresses, devices, and objects are synthetic. Addresses use documentation
 * ranges (RFC 5737).
 *
 * Usage: php shared/bin/generate-soc1.php
 */

require_once dirname(__DIR__) . '/lib/soc.php';

$root = soc_root();
$trainEvents = [];
$trainLabels = ['case_id' => 'SOC-1', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$seqEvents = [];
$counter = [];

$sensors = ['auth' => 'auth-api-1', 'session' => 'session-svc-1', 'api' => 'api-gateway-1'];

/**
 * Build one event, record its label, and attach it to an optional sequence.
 */
function makeEvent(
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
        'case_id' => 'SOC-1',
        'schema_version' => '1.0.0',
        'source' => $source,
        'event_time' => $time,
        'event_time_utc' => $utc,
        'sensor' => $sensors[$source],
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

$add = static function (
    string $prefix,
    string $source,
    string $time,
    array $fields,
    string $label,
    ?string $seqId
) use (&$trainEvents, &$trainLabels, &$seqEvents, &$counter, $sensors): string {
    return makeEvent($prefix, $source, $time, $fields, $label, $seqId, $trainEvents, $trainLabels, $seqEvents, $counter, $sensors);
};

$T = '2026-11-05T';
$tp = 'SOC1-T';

// --- Baseline: three ordinary accounts ------------------------------------
$baseline = [
    ['aurel@kampus.test', '08:05:00', '198.51.100.21', 'Jakarta', 'dev-aurel-laptop', 'S-AUR-1', 'STU-1001'],
    ['bima@kampus.test', '08:20:00', '198.51.100.22', 'Bandung', 'dev-bima-laptop', 'S-BIM-1', 'STU-1002'],
    ['citra@kampus.test', '08:40:00', '203.0.113.20', 'Surabaya', 'dev-citra-laptop', 'S-CIT-1', 'STU-1003'],
];
foreach ($baseline as [$account, $time, $ip, $geo, $device, $session, $object]) {
    $seq = null;
    $add($tp, 'auth', $T . $time . '+07:00', [
        'account' => $account, 'event_type' => 'auth.login', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'note' => 'Normal sign-in from the account baseline device.',
    ], 'benign', $seq);
    $add($tp, 'session', $T . $time . '+07:00', [
        'account' => $account, 'event_type' => 'session.created', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'note' => 'Session created after successful authentication.',
    ], 'benign', $seq);
    $add($tp, 'api', (new DateTimeImmutable($T . $time . '+07:00'))->modify('+2 minutes')->format('c'), [
        'account' => $account, 'event_type' => 'api.object.read', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'object_type' => 'student_record', 'object_id' => $object, 'bytes' => 940,
        'note' => 'Account reads its own record.',
    ], 'benign', $seq);
    $add($tp, 'api', (new DateTimeImmutable($T . $time . '+07:00'))->modify('+4 minutes')->format('c'), [
        'account' => $account, 'event_type' => 'api.object.read', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'object_type' => 'course', 'object_id' => 'COURSE-301', 'bytes' => 1520,
        'note' => 'Account reads a public course record.',
    ], 'benign', $seq);
    $add($tp, 'auth', (new DateTimeImmutable($T . $time . '+07:00'))->modify('+25 minutes')->format('c'), [
        'account' => $account, 'event_type' => 'auth.logout', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'note' => 'Normal sign-out.',
    ], 'benign', $seq);
}

// --- Intended chain: credential stuffing then bulk object access ----------
$atoBase = new DateTimeImmutable($T . '02:10:00+07:00');
for ($i = 0; $i < 5; $i++) {
    $add($tp, 'auth', $atoBase->modify("+{$i}0 seconds")->format('c'), [
        'account' => 'nadia@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'failure',
        'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77', 'geo' => 'VPN exit (synthetic)',
        'note' => 'Failed sign-in from an unfamiliar device and address.',
    ], 'malicious', 'SEQ-ATO-T1');
}
$add($tp, 'auth', $atoBase->modify('+2 minutes 30 seconds')->format('c'), [
    'account' => 'nadia@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-ATO-1', 'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'Successful sign-in after repeated failures.',
], 'malicious', 'SEQ-ATO-T1');
$add($tp, 'session', $atoBase->modify('+2 minutes 31 seconds')->format('c'), [
    'account' => 'nadia@kampus.test', 'event_type' => 'session.created', 'outcome' => 'success',
    'session_id' => 'S-ATO-1', 'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'New session from the unfamiliar device.',
], 'malicious', 'SEQ-ATO-T1');
for ($i = 1; $i <= 12; $i++) {
    $add($tp, 'api', $atoBase->modify('+2 minutes 40 seconds')->modify('+' . ($i * 15) . ' seconds')->format('c'), [
        'account' => 'nadia@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
        'session_id' => 'S-ATO-1', 'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77',
        'geo' => 'VPN exit (synthetic)', 'object_type' => 'student_record',
        'object_id' => sprintf('STU-%04d', 1100 + $i), 'bytes' => 880 + $i * 10,
        'note' => 'Sequential read of student records outside the account baseline.',
    ], 'malicious', 'SEQ-ATO-T1');
}
$add($tp, 'api', $atoBase->modify('+6 minutes')->format('c'), [
    'account' => 'nadia@kampus.test', 'event_type' => 'api.token.refresh', 'outcome' => 'success',
    'session_id' => 'S-ATO-1', 'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'Token refreshed after bulk reads.',
], 'malicious', 'SEQ-ATO-T1');
$add($tp, 'api', $atoBase->modify('+7 minutes')->format('c'), [
    'account' => 'nadia@kampus.test', 'event_type' => 'api.export', 'outcome' => 'success',
    'session_id' => 'S-ATO-1', 'device_id' => 'dev-unknown-1', 'src_ip' => '203.0.113.77',
    'geo' => 'VPN exit (synthetic)', 'object_type' => 'student_record_set', 'object_id' => 'SET-1101-1112',
    'bytes' => 48200, 'note' => 'Bulk export of the records read in this session.',
], 'malicious', 'SEQ-ATO-T1');

// --- Legitimate travel ---------------------------------------------------
$travel = new DateTimeImmutable($T . '09:00:00+07:00');
$add($tp, 'auth', $travel->format('c'), [
    'account' => 'budi@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-TRV-1', 'device_id' => 'dev-budi-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'role' => 'student',
    'note' => 'Approved conference travel window; device matches the account baseline.',
], 'benign', 'SEQ-TRV-T1');
$add($tp, 'session', $travel->modify('+1 second')->format('c'), [
    'account' => 'budi@kampus.test', 'event_type' => 'session.created', 'outcome' => 'success',
    'session_id' => 'S-TRV-1', 'device_id' => 'dev-budi-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'note' => 'Session created from the known travel device.',
], 'benign', 'SEQ-TRV-T1');
$add($tp, 'api', $travel->modify('+6 minutes')->format('c'), [
    'account' => 'budi@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
    'session_id' => 'S-TRV-1', 'device_id' => 'dev-budi-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'object_type' => 'student_record', 'object_id' => 'STU-2001', 'bytes' => 910,
    'note' => 'Reads own record only.',
], 'benign', 'SEQ-TRV-T1');
$add($tp, 'api', $travel->modify('+8 minutes')->format('c'), [
    'account' => 'budi@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
    'session_id' => 'S-TRV-1', 'device_id' => 'dev-budi-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'object_type' => 'course', 'object_id' => 'COURSE-301', 'bytes' => 1500,
    'note' => 'Reads a public course record.',
], 'benign', 'SEQ-TRV-T1');

// --- Password retry from the usual device --------------------------------
$retry = new DateTimeImmutable($T . '11:30:00+07:00');
for ($i = 0; $i < 3; $i++) {
    $add($tp, 'auth', $retry->modify("+{$i}0 seconds")->format('c'), [
        'account' => 'citra@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'failure',
        'device_id' => 'dev-citra-laptop', 'src_ip' => '203.0.113.20', 'geo' => 'Surabaya',
        'note' => 'Password retry from the usual device.',
    ], 'benign', 'SEQ-RET-T1');
}
$add($tp, 'auth', $retry->modify('+50 seconds')->format('c'), [
    'account' => 'citra@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-RET-1', 'device_id' => 'dev-citra-laptop', 'src_ip' => '203.0.113.20',
    'geo' => 'Surabaya', 'note' => 'Successful sign-in after a short retry sequence.',
], 'benign', 'SEQ-RET-T1');

// --- Scheduled administrator maintenance ---------------------------------
$admin = new DateTimeImmutable($T . '01:00:00+07:00');
$add($tp, 'auth', $admin->format('c'), [
    'account' => 'admin@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-ADM-1', 'device_id' => 'dev-admin-1', 'src_ip' => '192.0.2.10',
    'geo' => 'Jakarta', 'role' => 'administrator',
    'note' => 'Approved maintenance window on the admin host.',
], 'benign', 'SEQ-ADM-T1');
$add($tp, 'session', $admin->modify('+1 second')->format('c'), [
    'account' => 'admin@kampus.test', 'event_type' => 'session.created', 'outcome' => 'success',
    'session_id' => 'S-ADM-1', 'device_id' => 'dev-admin-1', 'src_ip' => '192.0.2.10',
    'geo' => 'Jakarta', 'note' => 'Admin session created.',
], 'benign', 'SEQ-ADM-T1');
$add($tp, 'api', $admin->modify('+5 minutes')->format('c'), [
    'account' => 'admin@kampus.test', 'event_type' => 'api.role.change', 'outcome' => 'success',
    'session_id' => 'S-ADM-1', 'device_id' => 'dev-admin-1', 'src_ip' => '192.0.2.10',
    'geo' => 'Jakarta', 'object_type' => 'role_binding', 'object_id' => 'RB-1042',
    'note' => 'Scheduled role maintenance recorded in the change calendar.',
], 'benign', 'SEQ-ADM-T1');

// --- Shared-address false lead ------------------------------------------
$distractor = new DateTimeImmutable($T . '10:00:00+07:00');
$add($tp, 'auth', $distractor->format('c'), [
    'account' => 'dimas@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-DIM-1', 'device_id' => 'dev-dimas-laptop', 'src_ip' => '203.0.113.77',
    'geo' => 'Jakarta',
    'note' => 'Same address as the suspicious chain, but a known device and ordinary behaviour.',
], 'benign', 'SEQ-NAT-T1');
$add($tp, 'api', $distractor->modify('+3 minutes')->format('c'), [
    'account' => 'dimas@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
    'session_id' => 'S-DIM-1', 'device_id' => 'dev-dimas-laptop', 'src_ip' => '203.0.113.77',
    'geo' => 'Jakarta', 'object_type' => 'student_record', 'object_id' => 'STU-3001', 'bytes' => 900,
    'note' => 'Reads own record only.',
], 'benign', 'SEQ-NAT-T1');

$trainSequences = [
    ['sequence_id' => 'SEQ-ATO-T1', 'label' => 'malicious', 'title' => 'Credential stuffing to bulk export',
     'event_ids' => $seqEvents['SEQ-ATO-T1'] ?? [],
     'explanation' => 'Repeated failures, success from the same unfamiliar device, sequential record reads, token refresh, then export.'],
    ['sequence_id' => 'SEQ-TRV-T1', 'label' => 'benign', 'title' => 'Approved travel sign-in',
     'event_ids' => $seqEvents['SEQ-TRV-T1'] ?? [],
     'explanation' => 'New geography but a known device, own-record access only, and an approved travel window.'],
    ['sequence_id' => 'SEQ-RET-T1', 'label' => 'benign', 'title' => 'Password retry',
     'event_ids' => $seqEvents['SEQ-RET-T1'] ?? [],
     'explanation' => 'Short failure run from the usual device, no object access afterwards.'],
    ['sequence_id' => 'SEQ-ADM-T1', 'label' => 'benign', 'title' => 'Scheduled admin maintenance',
     'event_ids' => $seqEvents['SEQ-ADM-T1'] ?? [],
     'explanation' => 'Recorded maintenance window on the admin host.'],
    ['sequence_id' => 'SEQ-NAT-T1', 'label' => 'benign', 'title' => 'Shared address, ordinary behaviour',
     'event_ids' => $seqEvents['SEQ-NAT-T1'] ?? [],
     'explanation' => 'Same source address as the suspicious chain but a known device and narrow access.'],
];
$trainLabels['sequences'] = $trainSequences;

// --- Holdout: same mechanics, different identities and addresses ---------
$holdoutEvents = [];
$holdoutLabels = ['case_id' => 'SOC-1', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$hseq = [];
$hcounter = [];
$hp = 'SOC1-H';
$addH = static function (string $source, string $time, array $fields, string $label, ?string $seqId)
    use (&$holdoutEvents, &$holdoutLabels, &$hseq, &$hcounter, $sensors, $hp): string {
    return makeEvent($hp, $source, $time, $fields, $label, $seqId, $holdoutEvents, $holdoutLabels, $hseq, $hcounter, $sensors);
};

$H = '2026-11-12T';
$hbaseline = [
    ['indra@kampus.test', '08:10:00', '198.51.100.31', 'Jakarta', 'dev-indra-laptop', 'S-IND-1', 'STU-4001'],
    ['maya@kampus.test', '08:30:00', '203.0.113.33', 'Medan', 'dev-maya-laptop', 'S-MAY-1', 'STU-4002'],
];
foreach ($hbaseline as [$account, $time, $ip, $geo, $device, $session, $object]) {
    $addH('auth', $H . $time . '+07:00', [
        'account' => $account, 'event_type' => 'auth.login', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'note' => 'Normal sign-in.', 'role' => 'student',
    ], 'benign', null);
    $addH('api', (new DateTimeImmutable($H . $time . '+07:00'))->modify('+3 minutes')->format('c'), [
        'account' => $account, 'event_type' => 'api.object.read', 'outcome' => 'success',
        'session_id' => $session, 'device_id' => $device, 'src_ip' => $ip, 'geo' => $geo,
        'object_type' => 'student_record', 'object_id' => $object, 'bytes' => 920,
        'note' => 'Reads own record.',
    ], 'benign', null);
}

$hAto = new DateTimeImmutable($H . '03:20:00+07:00');
for ($i = 0; $i < 4; $i++) {
    $addH('auth', $hAto->modify("+{$i}5 seconds")->format('c'), [
        'account' => 'fajar@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'failure',
        'device_id' => 'dev-unknown-9', 'src_ip' => '198.51.100.77', 'geo' => 'VPN exit (synthetic)',
        'note' => 'Failed sign-in from an unfamiliar device.', 'role' => 'student',
    ], 'malicious', 'SEQ-ATO-H1');
}
$addH('auth', $hAto->modify('+3 minutes')->format('c'), [
    'account' => 'fajar@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-ATO-H1', 'device_id' => 'dev-unknown-9', 'src_ip' => '198.51.100.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'Success after repeated failures.',
], 'malicious', 'SEQ-ATO-H1');
$addH('session', $hAto->modify('+3 minutes 1 second')->format('c'), [
    'account' => 'fajar@kampus.test', 'event_type' => 'session.created', 'outcome' => 'success',
    'session_id' => 'S-ATO-H1', 'device_id' => 'dev-unknown-9', 'src_ip' => '198.51.100.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'New session from the unfamiliar device.',
], 'malicious', 'SEQ-ATO-H1');
for ($i = 1; $i <= 9; $i++) {
    $addH('api', $hAto->modify('+3 minutes 10 seconds')->modify('+' . ($i * 15) . ' seconds')->format('c'), [
        'account' => 'fajar@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
        'session_id' => 'S-ATO-H1', 'device_id' => 'dev-unknown-9', 'src_ip' => '198.51.100.77',
        'geo' => 'VPN exit (synthetic)', 'object_type' => 'student_record',
        'object_id' => sprintf('STU-%04d', 5100 + $i), 'bytes' => 860 + $i * 12,
        'note' => 'Sequential reads outside the account baseline.',
    ], 'malicious', 'SEQ-ATO-H1');
}
$addH('api', $hAto->modify('+5 minutes')->format('c'), [
    'account' => 'fajar@kampus.test', 'event_type' => 'api.token.refresh', 'outcome' => 'success',
    'session_id' => 'S-ATO-H1', 'device_id' => 'dev-unknown-9', 'src_ip' => '198.51.100.77',
    'geo' => 'VPN exit (synthetic)', 'note' => 'Token refresh after bulk reads.',
], 'malicious', 'SEQ-ATO-H1');

$hTravel = new DateTimeImmutable($H . '09:15:00+07:00');
$addH('auth', $hTravel->format('c'), [
    'account' => 'gita@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-TRV-H1', 'device_id' => 'dev-gita-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'note' => 'Approved travel; known device.', 'role' => 'student',
], 'benign', 'SEQ-TRV-H1');
$addH('api', $hTravel->modify('+5 minutes')->format('c'), [
    'account' => 'gita@kampus.test', 'event_type' => 'api.object.read', 'outcome' => 'success',
    'session_id' => 'S-TRV-H1', 'device_id' => 'dev-gita-phone', 'src_ip' => '198.51.100.45',
    'geo' => 'Singapore', 'object_type' => 'student_record', 'object_id' => 'STU-6001', 'bytes' => 905,
    'note' => 'Reads own record only.',
], 'benign', 'SEQ-TRV-H1');

$hRetry = new DateTimeImmutable($H . '13:00:00+07:00');
for ($i = 0; $i < 2; $i++) {
    $addH('auth', $hRetry->modify("+{$i}0 seconds")->format('c'), [
        'account' => 'hana@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'failure',
        'device_id' => 'dev-hana-laptop', 'src_ip' => '203.0.113.40', 'geo' => 'Yogyakarta',
        'note' => 'Password retry from the usual device.', 'role' => 'student',
    ], 'benign', 'SEQ-RET-H1');
}
$addH('auth', $hRetry->modify('+30 seconds')->format('c'), [
    'account' => 'hana@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-RET-H1', 'device_id' => 'dev-hana-laptop', 'src_ip' => '203.0.113.40',
    'geo' => 'Yogyakarta', 'note' => 'Success after a short retry sequence.', 'role' => 'student',
], 'benign', 'SEQ-RET-H1');

$hAdmin = new DateTimeImmutable($H . '01:30:00+07:00');
$addH('auth', $hAdmin->format('c'), [
    'account' => 'admin2@kampus.test', 'event_type' => 'auth.login', 'outcome' => 'success',
    'session_id' => 'S-ADM-H1', 'device_id' => 'dev-admin-2', 'src_ip' => '192.0.2.11',
    'geo' => 'Jakarta', 'role' => 'administrator', 'note' => 'Scheduled maintenance window.',
], 'benign', 'SEQ-ADM-H1');
$addH('api', $hAdmin->modify('+4 minutes')->format('c'), [
    'account' => 'admin2@kampus.test', 'event_type' => 'api.role.change', 'outcome' => 'success',
    'session_id' => 'S-ADM-H1', 'device_id' => 'dev-admin-2', 'src_ip' => '192.0.2.11',
    'geo' => 'Jakarta', 'object_type' => 'role_binding', 'object_id' => 'RB-2044',
    'note' => 'Change recorded in the maintenance calendar.',
], 'benign', 'SEQ-ADM-H1');

$holdoutLabels['sequences'] = [
    ['sequence_id' => 'SEQ-ATO-H1', 'label' => 'malicious', 'title' => 'Credential stuffing to bulk reads',
     'event_ids' => $hseq['SEQ-ATO-H1'] ?? [], 'explanation' => 'Private holdout chain.'],
    ['sequence_id' => 'SEQ-TRV-H1', 'label' => 'benign', 'title' => 'Approved travel',
     'event_ids' => $hseq['SEQ-TRV-H1'] ?? [], 'explanation' => 'Known device, narrow access.'],
    ['sequence_id' => 'SEQ-RET-H1', 'label' => 'benign', 'title' => 'Password retry',
     'event_ids' => $hseq['SEQ-RET-H1'] ?? [], 'explanation' => 'Usual device, no bulk access.'],
    ['sequence_id' => 'SEQ-ADM-H1', 'label' => 'benign', 'title' => 'Scheduled admin',
     'event_ids' => $hseq['SEQ-ADM-H1'] ?? [], 'explanation' => 'Maintenance window.'],
];

// --- Write outputs -------------------------------------------------------
soc_write_events($root . '/data/soc-1/train/events.jsonl', $trainEvents);
soc_json_write($root . '/data/soc-1/train/labels.json', $trainLabels);
soc_write_events($root . '/data/soc-1/holdout/events.jsonl', $holdoutEvents);
soc_json_write($root . '/instructor-private/soc-1/holdout_labels.json', $holdoutLabels);
soc_json_write($root . '/instructor-private/soc-1/generation.json', [
    'case_id' => 'SOC-1',
    'schema_version' => '1.0.0',
    'generator' => 'shared/bin/generate-soc1.php',
    'seed' => 'fixed-construction-no-rng',
    'harness_version' => SOC_HARNESS_VERSION,
    'train_events' => count($trainEvents),
    'holdout_events' => count($holdoutEvents),
    'train_malicious' => count(array_filter($trainLabels['event_labels'], static fn ($l) => $l === 'malicious')),
    'holdout_malicious' => count(array_filter($holdoutLabels['event_labels'], static fn ($l) => $l === 'malicious')),
]);

printf("SOC-1 generated: train=%d events, holdout=%d events\n", count($trainEvents), count($holdoutEvents));
