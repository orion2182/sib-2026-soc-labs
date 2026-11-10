<?php
declare(strict_types=1);

/**
 * SOC lab harness: static event loading, schema validation, a small
 * documented rule engine, event/sequence metrics, and packaging helpers.
 *
 * The engine is deliberately small and inspectable. It is not a SIEM.
 */

const SOC_HARNESS_VERSION = '1.0.0';

function soc_root(): string
{
    return dirname(__DIR__, 2);
}

/**
 * Resolve a case directory in either layout:
 * builder repo: <root>/data/<case>/
 * student package: <root>/ with schema.json and train/ at the root
 */
function soc_case_dir(string $root, string $case): string
{
    if (is_file($root . '/data/' . $case . '/schema.json')) {
        return $root . '/data/' . $case;
    }
    if (is_file($root . '/schema.json')) {
        return $root;
    }
    return $root . '/data/' . $case;
}

function soc_json_read(string $path): array
{
    if (!is_file($path)) {
        throw new RuntimeException('missing file: ' . $path);
    }
    $data = json_decode((string) file_get_contents($path), true);
    if (!is_array($data)) {
        throw new RuntimeException('invalid JSON: ' . $path);
    }
    return $data;
}

function soc_json_write(string $path, array $data): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    file_put_contents($path, $json . "\n");
}

/** @return list<array> */
function soc_load_events(string $path): array
{
    if (!is_file($path)) {
        throw new RuntimeException('missing event file: ' . $path);
    }
    $events = [];
    $lineNo = 0;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $lineNo++;
        $event = json_decode($line, true);
        if (!is_array($event)) {
            throw new RuntimeException("invalid JSON at $path line $lineNo");
        }
        $events[] = $event;
    }
    return $events;
}

function soc_write_events(string $path, array $events): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    $lines = [];
    foreach ($events as $event) {
        $lines[] = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    file_put_contents($path, implode("\n", $lines) . "\n");
}

function soc_field_types(): array
{
    return [
        'string' => static fn ($v): bool => is_string($v),
        'integer' => static fn ($v): bool => is_int($v),
        'number' => static fn ($v): bool => is_int($v) || is_float($v),
        'boolean' => static fn ($v): bool => is_bool($v),
        'object' => static fn ($v): bool => is_array($v),
        'null' => static fn ($v): bool => $v === null,
    ];
}

/**
 * Validate events against a schema document.
 * @return list<string> human-readable errors
 */
function soc_validate_events(array $events, array $schema): array
{
    $errors = [];
    $required = $schema['required_fields'] ?? [];
    $fields = $schema['fields'] ?? [];
    $sources = $schema['sources'] ?? [];
    $types = soc_field_types();
    $seen = [];

    foreach ($events as $i => $event) {
        $at = 'event#' . ($i + 1);
        foreach ($required as $field) {
            if (!array_key_exists($field, $event) || $event[$field] === null || $event[$field] === '') {
                $errors[] = "$at missing required field '$field'";
            }
        }
        $id = $event['event_id'] ?? null;
        if (!is_string($id) || $id === '') {
            $errors[] = "$at has no event_id";
        } elseif (isset($seen[$id])) {
            $errors[] = "$at duplicate event_id '$id'";
        } else {
            $seen[$id] = true;
        }

        if (isset($event['case_id']) && isset($schema['case_id']) && $event['case_id'] !== $schema['case_id']) {
            $errors[] = "$at case_id mismatch: {$event['case_id']}";
        }
        if (isset($event['schema_version']) && isset($schema['schema_version']) && $event['schema_version'] !== $schema['schema_version']) {
            $errors[] = "$at schema_version mismatch: {$event['schema_version']}";
        }
        if ($sources && isset($event['source']) && !in_array($event['source'], $sources, true)) {
            $errors[] = "$at unknown source '{$event['source']}'";
        }

        if (isset($event['event_time'])) {
            try {
                $source = new DateTimeImmutable((string) $event['event_time']);
                $offset = $source->getOffset();
                if (strpos((string) $event['event_time'], 'Z') === false && !preg_match('/[+-]\d{2}:\d{2}$/', (string) $event['event_time'])) {
                    $errors[] = "$at event_time has no explicit UTC offset";
                }
                $expected = $source->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
                if (($event['event_time_utc'] ?? null) !== $expected) {
                    $errors[] = "$at event_time_utc does not match event_time (expected $expected)";
                }
            } catch (Throwable $e) {
                $errors[] = "$at event_time unparseable: {$event['event_time']}";
            }
        }

        foreach ($event as $field => $value) {
            if (!isset($fields[$field])) {
                $errors[] = "$at unknown field '$field' not declared in schema";
                continue;
            }
            $type = $fields[$field]['type'] ?? 'string';
            if (isset($types[$type]) && !$types[$type]($value)) {
                $errors[] = "$at field '$field' expected $type";
            }
        }
    }
    return $errors;
}

/** Validate that labels only reference known events and cover every event. */
function soc_validate_labels(array $labels, array $events): array
{
    $errors = [];
    $ids = [];
    foreach ($events as $event) {
        $ids[$event['event_id'] ?? ''] = true;
    }
    $labelled = $labels['event_labels'] ?? [];
    foreach ($labelled as $id => $label) {
        if (!isset($ids[$id])) {
            $errors[] = "label references unknown event '$id'";
        }
        if (!in_array($label, ['malicious', 'benign'], true)) {
            $errors[] = "event '$id' has invalid label '$label'";
        }
    }
    foreach ($ids as $id => $_) {
        if (!isset($labelled[$id])) {
            $errors[] = "event '$id' has no training label";
        }
    }
    foreach (($labels['sequences'] ?? []) as $seq) {
        foreach (($seq['event_ids'] ?? []) as $id) {
            if (!isset($ids[$id])) {
                $errors[] = "sequence '{$seq['sequence_id']}' references unknown event '$id'";
            }
        }
    }
    return $errors;
}

function soc_matches(array $filter, array $event): bool
{
    $all = $filter['all'] ?? [$filter];
    foreach ($all as $condition) {
        $field = $condition['field'] ?? '';
        $op = $condition['op'] ?? 'eq';
        $expected = $condition['value'] ?? null;
        $actual = $event[$field] ?? null;
        $ok = match ($op) {
            'eq' => $actual == $expected,
            'ne' => $actual != $expected,
            'in' => is_array($expected) && in_array($actual, $expected, true),
            'contains' => is_string($actual) && str_contains($actual, (string) $expected),
            'startswith' => is_string($actual) && str_starts_with($actual, (string) $expected),
            'gt' => is_numeric($actual) && $actual > $expected,
            'lt' => is_numeric($actual) && $actual < $expected,
            'exists' => $expected ? $actual !== null : $actual === null,
            default => false,
        };
        if (!$ok) {
            return false;
        }
    }
    return true;
}

function soc_validate_rule(array $rule, array $schema): array
{
    $errors = [];
    $fields = $schema['fields'] ?? [];
    $conditions = [];
    if (isset($rule['stages'])) {
        if (!is_array($rule['stages']) || $rule['stages'] === []) {
            $errors[] = 'stages must be a non-empty array';
        }
        foreach (($rule['stages'] ?? []) as $si => $stage) {
            foreach (($stage['all'] ?? [$stage]) as $condition) {
                $conditions[] = $condition;
            }
        }
        if (!isset($rule['group_by']) || !is_string($rule['group_by'])) {
            $errors[] = 'sequence rule requires group_by';
        } elseif (!isset($fields[$rule['group_by']])) {
            $errors[] = 'group_by references unknown field ' . $rule['group_by'];
        }
        if (!isset($rule['within_seconds']) || !is_int($rule['within_seconds']) || $rule['within_seconds'] <= 0) {
            $errors[] = 'sequence rule requires a positive integer within_seconds';
        }
    } else {
        $conditions = $rule['where']['all'] ?? [$rule['where'] ?? []];
    }
    foreach ($conditions as $condition) {
        $field = $condition['field'] ?? '';
        if (!isset($fields[$field])) {
            $errors[] = "rule references unknown field '$field'";
        }
        $validOps = ['eq', 'ne', 'in', 'contains', 'startswith', 'gt', 'lt', 'exists'];
        if (!in_array($condition['op'] ?? 'eq', $validOps, true)) {
            $errors[] = "unsupported operator '{$condition['op']}' on field '$field'";
        }
    }
    return $errors;
}

function soc_time(string $value): int
{
    return (new DateTimeImmutable($value))->getTimestamp();
}

/**
 * Evaluate a rule.
 * @return array{matched_ids:list<string>, errors:list<string>}
 */
function soc_evaluate(array $events, array $rule, array $schema): array
{
    $errors = soc_validate_rule($rule, $schema);
    if ($errors) {
        return ['matched_ids' => [], 'errors' => $errors];
    }
    $matched = [];

    if (!isset($rule['stages'])) {
        foreach ($events as $event) {
            if (soc_matches($rule['where'], $event)) {
                $matched[$event['event_id']] = true;
            }
        }
        return ['matched_ids' => array_keys($matched), 'errors' => []];
    }

    $groupBy = $rule['group_by'];
    $window = (int) $rule['within_seconds'];
    $stages = $rule['stages'];
    $groups = [];
    foreach ($events as $event) {
        $groups[(string) ($event[$groupBy] ?? '')][] = $event;
    }
    foreach ($groups as $groupEvents) {
        usort($groupEvents, static fn (array $a, array $b): int => soc_time($a['event_time_utc']) <=> soc_time($b['event_time_utc']));
        $count = count($groupEvents);
        for ($i = 0; $i < $count; $i++) {
            if (!soc_matches($stages[0], $groupEvents[$i])) {
                continue;
            }
            $chain = [$groupEvents[$i]['event_id']];
            $startTime = soc_time($groupEvents[$i]['event_time_utc']);
            $cursor = $i;
            $complete = true;
            for ($s = 1, $stageCount = count($stages); $s < $stageCount; $s++) {
                $found = false;
                for ($j = $cursor + 1; $j < $count; $j++) {
                    if (soc_time($groupEvents[$j]['event_time_utc']) - $startTime > $window) {
                        break;
                    }
                    if (soc_matches($stages[$s], $groupEvents[$j])) {
                        $chain[] = $groupEvents[$j]['event_id'];
                        $cursor = $j;
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $complete = false;
                    break;
                }
            }
            if ($complete) {
                foreach ($chain as $id) {
                    $matched[$id] = true;
                }
            }
        }
    }
    return ['matched_ids' => array_keys($matched), 'errors' => []];
}

/**
 * Event-level confusion matrix. A positive prediction on a malicious event is
 * TP; on a benign event FP; an un matched malicious event is FN.
 */
function soc_metrics(array $labels, array $matchedIds): array
{
    $labelled = $labels['event_labels'] ?? [];
    $matched = array_fill_keys($matchedIds, true);
    $tp = $fp = $fn = $tn = 0;
    $tpIds = $fpIds = $fnIds = [];
    foreach ($labelled as $id => $label) {
        $isMatched = isset($matched[$id]);
        $isMalicious = $label === 'malicious';
        if ($isMatched && $isMalicious) { $tp++; $tpIds[] = $id; }
        elseif ($isMatched && !$isMalicious) { $fp++; $fpIds[] = $id; }
        elseif (!$isMatched && $isMalicious) { $fn++; $fnIds[] = $id; }
        else { $tn++; }
    }
    $precision = ($tp + $fp) > 0 ? $tp / ($tp + $fp) : 0.0;
    $recall = ($tp + $fn) > 0 ? $tp / ($tp + $fn) : 0.0;
    $f1 = ($precision + $recall) > 0 ? 2 * $precision * $recall / ($precision + $recall) : 0.0;
    $fpr = ($fp + $tn) > 0 ? $fp / ($fp + $tn) : 0.0;
    return [
        'unit' => 'event',
        'counts' => ['tp' => $tp, 'fp' => $fp, 'fn' => $fn, 'tn' => $tn],
        'rates' => [
            'precision' => round($precision, 4),
            'recall' => round($recall, 4),
            'f1' => round($f1, 4),
            'false_positive_rate' => round($fpr, 4),
        ],
        'examples' => ['tp' => $tpIds, 'fp' => $fpIds, 'fn' => $fnIds],
    ];
}

function soc_sequence_coverage(array $labels, array $matchedIds): array
{
    $matched = array_fill_keys($matchedIds, true);
    $rows = [];
    foreach (($labels['sequences'] ?? []) as $seq) {
        $ids = $seq['event_ids'] ?? [];
        $hits = array_values(array_filter($ids, static fn (string $id): bool => isset($matched[$id])));
        $rows[] = [
            'sequence_id' => $seq['sequence_id'] ?? '?',
            'label' => $seq['label'] ?? '?',
            'events' => count($ids),
            'matched' => count($hits),
            'detected' => count($ids) > 0 && count($hits) === count($ids),
            'partially_detected' => count($hits) > 0,
        ];
    }
    return $rows;
}

function soc_sha256(string $path): string
{
    if (!is_file($path)) {
        return '';
    }
    $hash = hash_file('sha256', $path);
    return $hash === false ? '' : $hash;
}

function soc_manifest(string $root, array $exclude = ['manifest-sha256.txt']): array
{
    $lines = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );
    $files = [];
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
        if (in_array($rel, $exclude, true)) {
            continue;
        }
        $files[$rel] = $file->getPathname();
    }
    ksort($files);
    foreach ($files as $rel => $path) {
        $lines[] = hash_file('sha256', $path) . '  ' . $rel;
    }
    return $lines;
}

/** Evaluate a rule file and emit a reproducible report. */
function soc_report(array $events, array $labels, array $rule, array $schema, array $meta = []): array
{
    $result = soc_evaluate($events, $rule, $schema);
    if ($result['errors']) {
        return ['ok' => false, 'errors' => $result['errors']];
    }
    $metrics = soc_metrics($labels, $result['matched_ids']);
    return [
        'ok' => true,
        'generated_at_utc' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z'),
        'rule' => $rule['name'] ?? 'unnamed',
        'rule_version' => $rule['version'] ?? 1,
        'dataset' => $meta['dataset'] ?? null,
        'dataset_sha256' => $meta['dataset_sha256'] ?? null,
        'schema_version' => $schema['schema_version'] ?? null,
        'evaluator_version' => SOC_HARNESS_VERSION,
        'matched_ids' => $result['matched_ids'],
        'metrics' => $metrics,
        'sequence_coverage' => soc_sequence_coverage($labels, $result['matched_ids']),
    ];
}
