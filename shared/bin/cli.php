<?php
declare(strict_types=1);

/**
 * SOC lab CLI: generate, validate, evaluate, freeze, package.
 *
 * Examples:
 *   php shared/bin/cli.php generate
 *   php shared/bin/cli.php validate --case soc-1
 *   php shared/bin/cli.php evaluate --case soc-1 --rule my-rule.json --split train
 *   php shared/bin/cli.php evaluate --case soc-1 --rule instructor-private/soc-1/reference_rule.json --split holdout --instructor
 *   php shared/bin/cli.php package --case soc-1
 */

require_once dirname(__DIR__) . '/lib/soc.php';

function arg(array $argv, string $name, ?string $default = null): ?string
{
    $index = array_search('--' . $name, $argv, true);
    if ($index === false) {
        return $default;
    }
    return $argv[$index + 1] ?? $default;
}

function flag(array $argv, string $name): bool
{
    return in_array('--' . $name, $argv, true);
}

$command = $argv[1] ?? 'help';
$root = soc_root();
$case = (string) arg($argv, 'case', 'soc-1');
$caseDir = soc_case_dir($root, $case);

switch ($command) {
    case 'generate':
        require __DIR__ . '/generate-soc1.php';
        break;

    case 'validate':
        $schema = soc_json_read($caseDir . '/schema.json');
        $trainEvents = soc_load_events($caseDir . '/train/events.jsonl');
        $trainLabels = soc_json_read($caseDir . '/train/labels.json');
        $errors = array_merge(
            soc_validate_events($trainEvents, $schema),
            soc_validate_labels($trainLabels, $trainEvents)
        );
        $holdoutEvents = soc_load_events($caseDir . '/holdout/events.jsonl');
        $errors = array_merge($errors, soc_validate_events($holdoutEvents, $schema));

        $privateLabelsPath = $root . '/instructor-private/' . $case . '/holdout_labels.json';
        if (is_file($privateLabelsPath)) {
            $errors = array_merge($errors, soc_validate_labels(soc_json_read($privateLabelsPath), $holdoutEvents));
        }
        if ($errors) {
            fwrite(STDERR, "VALIDATION FAILED (" . count($errors) . ")\n");
            foreach (array_slice($errors, 0, 50) as $error) {
                fwrite(STDERR, "  - $error\n");
            }
            exit(1);
        }
        printf(
            "VALID ok: case=%s train=%d holdout=%d schema=%s\n",
            $case,
            count($trainEvents),
            count($holdoutEvents),
            $schema['schema_version']
        );
        printf("train_events.sha256=%s\n", soc_sha256($caseDir . '/train/events.jsonl'));
        printf("holdout_events.sha256=%s\n", soc_sha256($caseDir . '/holdout/events.jsonl'));
        break;

    case 'evaluate':
        $rulePath = (string) arg($argv, 'rule', '');
        if ($rulePath === '' || !is_file($rulePath)) {
            fwrite(STDERR, "missing --rule <path>\n");
            exit(2);
        }
        $split = (string) arg($argv, 'split', 'train');
        if ($split === 'holdout' && !flag($argv, 'instructor')) {
            fwrite(STDERR, "holdout scoring is mentor-only; add --instructor on a mentor machine\n");
            exit(3);
        }
        $schema = soc_json_read($caseDir . '/schema.json');
        $rule = soc_json_read($rulePath);
        if ($split === 'train') {
            $events = soc_load_events($caseDir . '/train/events.jsonl');
            $labels = soc_json_read($caseDir . '/train/labels.json');
            $dataset = $caseDir . '/train/events.jsonl';
        } else {
            $events = soc_load_events($caseDir . '/holdout/events.jsonl');
            $labels = soc_json_read($root . '/instructor-private/' . $case . '/holdout_labels.json');
            $dataset = $caseDir . '/holdout/events.jsonl';
        }
        $report = soc_report($events, $labels, $rule, $schema, [
            'dataset' => $split,
            'dataset_sha256' => soc_sha256($dataset),
        ]);
        if (!$report['ok']) {
            fwrite(STDERR, "RULE REJECTED\n");
            foreach ($report['errors'] as $error) {
                fwrite(STDERR, "  - $error\n");
            }
            exit(1);
        }
        $out = arg($argv, 'out');
        if ($out) {
            soc_json_write($out, $report);
            printf("Report written to %s\n", $out);
        } else {
            echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        }
        printf(
            "TP=%d FP=%d FN=%d TN=%d precision=%.4f recall=%.4f\n",
            $report['metrics']['counts']['tp'],
            $report['metrics']['counts']['fp'],
            $report['metrics']['counts']['fn'],
            $report['metrics']['counts']['tn'],
            $report['metrics']['rates']['precision'],
            $report['metrics']['rates']['recall']
        );
        break;

    case 'freeze':
        $rulePath = (string) arg($argv, 'rule', '');
        if ($rulePath === '' || !is_file($rulePath)) {
            fwrite(STDERR, "missing --rule <path>\n");
            exit(2);
        }
        $freeze = [
            'case_id' => strtoupper($case),
            'frozen_at_utc' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z'),
            'rule_path' => $rulePath,
            'rule_sha256' => soc_sha256($rulePath),
            'schema_sha256' => soc_sha256($caseDir . '/schema.json'),
            'train_sha256' => soc_sha256($caseDir . '/train/events.jsonl'),
            'holdout_sha256' => soc_sha256($caseDir . '/holdout/events.jsonl'),
            'evaluator_sha256' => soc_sha256($root . '/shared/lib/soc.php'),
            'evaluator_version' => SOC_HARNESS_VERSION,
        ];
        $out = (string) arg($argv, 'out', $root . '/instructor-private/' . $case . '/freeze.json');
        soc_json_write($out, $freeze);
        echo json_encode($freeze, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        break;

    case 'package':
        $packageRoot = $root . '/packages';
        if (!is_dir($packageRoot)) {
            mkdir($packageRoot, 0777, true);
        }
        $staging = $packageRoot . '/.staging-' . $case;
        if (is_dir($staging)) {
            $cleanup = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($staging, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($cleanup as $item) {
                $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
            }
            rmdir($staging);
        }
        mkdir($staging, 0777, true);

        $copy = static function (string $from, string $to) use ($staging): void {
            $dest = $staging . '/' . $to;
            if (!is_dir(dirname($dest))) {
                mkdir(dirname($dest), 0777, true);
            }
            if (is_dir($from)) {
                if (!is_dir($dest)) {
                    mkdir($dest, 0777, true);
                }
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($from, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($it as $item) {
                    $rel = ltrim(str_replace('\\', '/', substr($item->getPathname(), strlen($from))), '/');
                    $target = $dest . '/' . $rel;
                    if ($item->isDir()) {
                        if (!is_dir($target)) {
                            mkdir($target, 0777, true);
                        }
                    } else {
                        if (!is_dir(dirname($target))) {
                            mkdir(dirname($target), 0777, true);
                        }
                        copy($item->getPathname(), $target);
                    }
                }
            } else {
                copy($from, $dest);
            }
        };

        $copy($caseDir . '/schema.json', 'schema.json');
        foreach (['data-dictionary.md', 'student-card.md', 'README-mahasiswa.md'] as $doc) {
            if (is_file($caseDir . '/' . $doc)) {
                $copy($caseDir . '/' . $doc, $doc);
            }
        }
        $copy($caseDir . '/train/events.jsonl', 'train/events.jsonl');
        $copy($caseDir . '/train/labels.json', 'train/labels.json');
        $copy($caseDir . '/holdout/events.jsonl', 'holdout/events.jsonl');
        $copy($root . '/shared/lib', 'shared/lib');
        $copy($root . '/shared/public', 'shared/public');
        $copy($root . '/shared/bin/cli.php', 'shared/bin/cli.php');
        $copy($root . '/tools/soc.ps1', 'tools/soc.ps1');

        $manifest = soc_manifest($staging);
        file_put_contents($staging . '/manifest-sha256.txt', implode("\n", $manifest) . "\n");

        $zip = $packageRoot . '/' . $case . '-student.zip';
        if (is_file($zip)) {
            unlink($zip);
        }
        $zipArchive = new ZipArchive();
        if ($zipArchive->open($zip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('cannot create zip');
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($staging, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $item) {
            $rel = str_replace('\\', '/', substr($item->getPathname(), strlen($staging) + 1));
            $item->isDir() ? $zipArchive->addEmptyDir($rel) : $zipArchive->addFile($item->getPathname(), $rel);
        }
        $zipArchive->close();
        printf("Package: %s\n", $zip);
        printf("SHA256:  %s\n", soc_sha256($zip));
        printf("Files:   %d\n", count($manifest));
        break;

    case 'selfcheck':
        $schema = soc_json_read($caseDir . '/schema.json');
        $rulePath = $root . '/instructor-private/' . $case . '/reference_rule.json';
        if (!is_file($rulePath)) {
            fwrite(STDERR, "missing reference rule\n");
            exit(2);
        }
        $rule = soc_json_read($rulePath);
        $trainEvents = soc_load_events($caseDir . '/train/events.jsonl');
        $trainLabels = soc_json_read($caseDir . '/train/labels.json');
        $train = soc_report($trainEvents, $trainLabels, $rule, $schema, [
            'dataset' => 'train', 'dataset_sha256' => soc_sha256($caseDir . '/train/events.jsonl'),
        ]);
        $holdoutEvents = soc_load_events($caseDir . '/holdout/events.jsonl');
        $holdoutLabels = soc_json_read($root . '/instructor-private/' . $case . '/holdout_labels.json');
        $holdout = soc_report($holdoutEvents, $holdoutLabels, $rule, $schema, [
            'dataset' => 'holdout', 'dataset_sha256' => soc_sha256($caseDir . '/holdout/events.jsonl'),
        ]);
        if (!$train['ok'] || !$holdout['ok']) {
            fwrite(STDERR, "reference rule rejected\n");
            exit(1);
        }
        // Re-run to prove determinism.
        $again = soc_report($trainEvents, $trainLabels, $rule, $schema, [
            'dataset' => 'train', 'dataset_sha256' => soc_sha256($caseDir . '/train/events.jsonl'),
        ]);
        $deterministic = $train['matched_ids'] === $again['matched_ids']
            && $train['metrics'] === $again['metrics'];
        $summary = [
            'case_id' => 'SOC-1',
            'schema_version' => $schema['schema_version'],
            'rule' => $rule['name'] ?? 'unnamed',
            'rule_sha256' => soc_sha256($rulePath),
            'train' => $train['metrics']['counts'],
            'holdout' => $holdout['metrics']['counts'],
            'train_sequences' => $train['sequence_coverage'],
            'holdout_sequences' => $holdout['sequence_coverage'],
            'deterministic_repeat' => $deterministic,
        ];
        soc_json_write($root . '/instructor-private/' . $case . '/expected_metrics.json', $summary);
        echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        if (!$deterministic) {
            fwrite(STDERR, "non-deterministic evaluation\n");
            exit(1);
        }
        break;

    default:
        echo "SOC lab CLI\n";
        echo "  php shared/bin/cli.php generate\n";
        echo "  php shared/bin/cli.php validate --case soc-1\n";
        echo "  php shared/bin/cli.php evaluate --case soc-1 --rule FILE --split train\n";
        echo "  php shared/bin/cli.php evaluate --case soc-1 --rule FILE --split holdout --instructor\n";
        echo "  php shared/bin/cli.php freeze --case soc-1 --rule FILE\n";
        echo "  php shared/bin/cli.php package --case soc-1\n";
        echo "  php shared/bin/cli.php selfcheck --case soc-1\n";
        break;
}
