<?php
declare(strict_types=1);

/**
 * Deterministic SOC-3 (DNS/network beacon) generator.
 * Static inert records only; no packet replay or outbound traffic.
 */

require_once dirname(__DIR__) . '/lib/soc.php';

$root = soc_root();
$sensors = ['dns' => 'zeek-dns-1', 'conn' => 'zeek-conn-1', 'ids' => 'suricata-1'];
$counter = [];

function neutral_note(string $type): string
{
    return match (true) {
        str_starts_with($type, 'dns.') => 'dns record',
        str_starts_with($type, 'conn.') => 'connection record',
        str_starts_with($type, 'ids.') => 'ids record',
        default => 'source record',
    };
}

function s3_event(
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
        'case_id' => 'SOC-3',
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
    $event['note'] = neutral_note((string) $event['event_type']);
    $events[] = $event;
    $labels['event_labels'][$id] = $label;
    if ($seqId !== null) {
        $seqEvents[$seqId][] = $id;
    }
    return $id;
}

function build_soc3(string $prefix, string $day, array &$events, array &$labels, array &$seqEvents, array $sensors): void
{
    $counter = [];
    $add = static function (string $source, string $time, array $fields, string $label, ?string $seqId = null)
        use (&$events, &$labels, &$seqEvents, &$counter, $sensors, $prefix): string {
        return s3_event($prefix, $source, $time, $fields, $label, $seqId, $events, $labels, $seqEvents, $counter, $sensors);
    };
    $T = $day . 'T';

    // Ordinary DNS background.
    $noise = [
        ['01:02:00', 'WS-0501', 'aurel@kampus.test', 'portal.kampus.test', '198.51.100.10'],
        ['01:03:00', 'WS-0501', 'aurel@kampus.test', 'mail.kampus.test', '198.51.100.11'],
        ['01:05:00', 'WS-0601', 'bima@kampus.test', 'lms.kampus.test', '198.51.100.12'],
        ['01:07:00', 'WS-0601', 'bima@kampus.test', 'cdn.example.test', '198.51.100.13'],
        ['01:09:00', 'WS-0501', 'aurel@kampus.test', 'docs.example.test', '198.51.100.14'],
        ['01:11:00', 'WS-0601', 'bima@kampus.test', 'search.example.test', '198.51.100.15'],
    ];
    foreach ($noise as [$time, $host, $account, $query, $answer]) {
        $add('dns', $T . $time . '+07:00', [
            'host' => $host, 'account' => $account, 'event_type' => 'dns.query', 'outcome' => 'success',
            'query' => $query, 'qtype' => 'A', 'rcode' => 'NOERROR', 'answers' => $answer,
            'proto' => 'udp', 'dest_port' => 53, 'note' => 'Ordinary lookup.',
        ], 'benign');
    }

    // Intended beacon: periodic DNS then small outbound connections.
    $base = new DateTimeImmutable($T . '01:20:00+07:00');
    $offsets = [0, 298, 603, 899, 1202, 1498];
    foreach ($offsets as $i => $offset) {
        $t = $base->modify("+{$offset} seconds");
        $add('dns', $t->format('c'), [
            'host' => 'WS-0501', 'account' => 'appsvc@kampus.test', 'event_type' => 'dns.query', 'outcome' => 'success',
            'query' => 'sync-a1b2c3.telemetry-sink.example', 'qtype' => 'A', 'rcode' => 'NOERROR',
            'answers' => '203.0.113.90', 'proto' => 'udp', 'dest_port' => 53,
            'note' => 'Repeated lookup with a changing subdomain label.',
        ], 'malicious', 'SEQ-BEACON-T1');
        $add('conn', $t->modify('+2 seconds')->format('c'), [
            'host' => 'WS-0501', 'account' => 'appsvc@kampus.test', 'event_type' => 'conn.flow', 'outcome' => 'success',
            'dest_ip' => '203.0.113.90', 'dest_port' => 443, 'proto' => 'tcp', 'duration' => 1.2,
            'orig_bytes' => 480 + $i * 4, 'resp_bytes' => 320, 'flow_id' => 'F-BEACON-' . $i,
            'process_name' => 'svchost.exe', 'note' => 'Small periodic connection after the lookup.',
        ], 'malicious', 'SEQ-BEACON-T1');
    }
    $add('ids', $base->modify('+2 seconds 500 milliseconds')->format('c'), [
        'host' => 'WS-0501', 'account' => 'appsvc@kampus.test', 'event_type' => 'ids.alert', 'outcome' => 'allowed',
        'dest_ip' => '203.0.113.90', 'dest_port' => 443, 'proto' => 'tcp', 'flow_id' => 'F-BEACON-0',
        'signature' => 'ET-MALWARE Synthetic Beacon Pattern', 'category' => 'Potential C2', 'severity' => 1,
        'note' => 'IDS alert corroborated by DNS and connection records.',
    ], 'malicious', 'SEQ-BEACON-T1');
    $add('ids', $base->modify('+899 seconds 3 seconds')->format('c'), [
        'host' => 'WS-0501', 'account' => 'appsvc@kampus.test', 'event_type' => 'ids.alert', 'outcome' => 'allowed',
        'dest_ip' => '203.0.113.90', 'dest_port' => 443, 'proto' => 'tcp', 'flow_id' => 'F-BEACON-3',
        'signature' => 'ET-MALWARE Synthetic Beacon Pattern', 'category' => 'Potential C2', 'severity' => 1,
        'note' => 'Second corroborated alert later in the same pattern.',
    ], 'malicious', 'SEQ-BEACON-T1');

    // Legitimate update polling.
    $upd = new DateTimeImmutable($T . '02:00:00+07:00');
    for ($i = 0; $i < 2; $i++) {
        $t = $upd->modify('+' . ($i * 3600) . ' seconds');
        $add('dns', $t->format('c'), [
            'host' => 'WS-0601', 'account' => 'updsvc@kampus.test', 'event_type' => 'dns.query', 'outcome' => 'success',
            'query' => 'updates.vendor.example', 'qtype' => 'A', 'rcode' => 'NOERROR',
            'answers' => '198.51.100.20', 'proto' => 'udp', 'dest_port' => 53,
            'note' => 'Scheduled updater lookup.',
        ], 'benign', 'SEQ-UPD-T1');
        $add('conn', $t->modify('+1 second')->format('c'), [
            'host' => 'WS-0601', 'account' => 'updsvc@kampus.test', 'event_type' => 'conn.flow', 'outcome' => 'success',
            'dest_ip' => '198.51.100.20', 'dest_port' => 443, 'proto' => 'tcp', 'duration' => 8.4,
            'orig_bytes' => 2200, 'resp_bytes' => 184000, 'flow_id' => 'F-UPD-' . $i,
            'process_name' => 'updater.exe', 'note' => 'Hourly update poll from the approved updater.',
        ], 'benign', 'SEQ-UPD-T1');
    }
    $add('ids', $upd->modify('+1 second 400 milliseconds')->format('c'), [
        'host' => 'WS-0601', 'account' => 'updsvc@kampus.test', 'event_type' => 'ids.alert', 'outcome' => 'allowed',
        'dest_ip' => '198.51.100.20', 'dest_port' => 443, 'proto' => 'tcp', 'flow_id' => 'F-UPD-0',
        'signature' => 'ET-INFO Periodic HTTPS Traffic', 'category' => 'Informational', 'severity' => 3,
        'note' => 'Low-severity alert on approved update polling; false-positive pressure.',
    ], 'benign', 'SEQ-UPD-T1');

    // Alert without corroborating traffic.
    $add('ids', $T . '04:15:00+07:00', [
        'host' => 'WS-0601', 'account' => 'bima@kampus.test', 'event_type' => 'ids.alert', 'outcome' => 'allowed',
        'dest_ip' => '192.0.2.77', 'dest_port' => 8443, 'proto' => 'tcp', 'flow_id' => 'F-ORPHAN-1',
        'signature' => 'ET-POLICY Outbound C2 Lookup', 'category' => 'Policy', 'severity' => 2,
        'note' => 'No matching DNS or connection record; the hypothesis remains unconfirmed.',
    ], 'benign', 'SEQ-ALERT-T1');

    $labels['label_semantics'] = 'malicious = part of the confirmed beacon pattern. benign = not part of a confirmed incident; an uncorroborated alert may still deserve triage.';
    $labels['sequences'] = [
        ['sequence_id' => 'SEQ-BEACON-T1', 'label' => 'malicious', 'title' => 'Periodic DNS and callback pattern',
         'event_ids' => $seqEvents['SEQ-BEACON-T1'] ?? [], 'explanation' => 'Six near-300-second lookups, small TLS flows, and two corroborating alerts.'],
        ['sequence_id' => 'SEQ-UPD-T1', 'label' => 'benign', 'title' => 'Approved hourly update polling',
         'event_ids' => $seqEvents['SEQ-UPD-T1'] ?? [], 'explanation' => 'Hourly poll from updater.exe to an approved vendor, with one low-severity alert.'],
        ['sequence_id' => 'SEQ-ALERT-T1', 'label' => 'benign', 'title' => 'Alert without traffic',
         'event_ids' => $seqEvents['SEQ-ALERT-T1'] ?? [], 'explanation' => 'An IDS alert with no DNS or connection evidence.'],
    ];
}

$trainEvents = [];
$trainLabels = ['case_id' => 'SOC-3', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$trainSeq = [];
build_soc3('SOC3-T', '2026-11-05', $trainEvents, $trainLabels, $trainSeq, $sensors);

$holdoutEvents = [];
$holdoutLabels = ['case_id' => 'SOC-3', 'schema_version' => '1.0.0', 'event_labels' => [], 'sequences' => []];
$holdoutSeq = [];
build_soc3('SOC3-H', '2026-11-12', $holdoutEvents, $holdoutLabels, $holdoutSeq, $sensors);

// Different hosts, domain, address, and flow ids in the holdout.
foreach ($holdoutEvents as &$event) {
    if (isset($event['host'])) {
        $event['host'] = str_replace('WS-0', 'WS-1', (string) $event['host']);
    }
    if (($event['query'] ?? '') === 'sync-a1b2c3.telemetry-sink.example') {
        $event['query'] = 'sync-z9y8x7.metrics-sync.example';
    }
    if (($event['dest_ip'] ?? '') === '203.0.113.90') {
        $event['dest_ip'] = '198.51.100.90';
    }
    if (isset($event['answers']) && $event['answers'] === '203.0.113.90') {
        $event['answers'] = '198.51.100.90';
    }
    if (isset($event['flow_id'])) {
        $event['flow_id'] = str_replace('F-BEACON', 'F-HBEACON', (string) $event['flow_id']);
    }
}
unset($event);

soc_write_events($root . '/data/soc-3/train/events.jsonl', $trainEvents);
soc_json_write($root . '/data/soc-3/train/labels.json', $trainLabels);
soc_write_events($root . '/data/soc-3/holdout/events.jsonl', $holdoutEvents);
soc_json_write($root . '/instructor-private/soc-3/holdout_labels.json', $holdoutLabels);
soc_json_write($root . '/instructor-private/soc-3/generation.json', [
    'case_id' => 'SOC-3',
    'schema_version' => '1.0.0',
    'generator' => 'shared/bin/generate-soc3.php',
    'seed' => 'fixed-construction-no-rng',
    'harness_version' => SOC_HARNESS_VERSION,
    'train_events' => count($trainEvents),
    'holdout_events' => count($holdoutEvents),
    'train_malicious' => count(array_filter($trainLabels['event_labels'], static fn ($l) => $l === 'malicious')),
    'holdout_malicious' => count(array_filter($holdoutLabels['event_labels'], static fn ($l) => $l === 'malicious')),
]);

printf("SOC-3 generated: train=%d events, holdout=%d events\n", count($trainEvents), count($holdoutEvents));
