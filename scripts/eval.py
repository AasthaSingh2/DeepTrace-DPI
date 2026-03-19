#!/usr/bin/env python3
import argparse
import csv
import sys


CANONICAL_LABELS = {
    "twitter": "X",
    "x": "X",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate DeepTrace-DPI predictions against flow labels."
    )
    parser.add_argument("--pred", required=True, help="Path to predictions.csv")
    parser.add_argument("--labels", required=True, help="Path to labels.csv")
    return parser.parse_args()


def read_csv_rows(path):
    with open(path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file has no header row: {path}")
        return reader.fieldnames, list(reader)


def detect_label_column(fieldnames):
    candidates = ("label", "true_label", "ground_truth", "app", "actual_app")
    lowered_to_original = {name.lower(): name for name in fieldnames}

    for candidate in candidates:
        if candidate in lowered_to_original:
            return lowered_to_original[candidate]

    raise ValueError(
        "labels.csv must contain one of these columns: "
        "label, true_label, ground_truth, app, actual_app"
    )


def normalize_label(label):
    normalized = (label or "").strip()
    if not normalized:
        return "Unknown"
    return CANONICAL_LABELS.get(normalized.casefold(), normalized)


def build_prediction_map(rows):
    prediction_map = {}
    for row in rows:
        flow_id = (row.get("flow_id") or "").strip()
        predicted_app = normalize_label(row.get("predicted_app"))
        if not flow_id:
            continue
        prediction_map[flow_id] = predicted_app
    return prediction_map


def build_pairs(predictions, label_rows, label_column):
    pairs = []
    missing_predictions = 0

    for row in label_rows:
        flow_id = (row.get("flow_id") or "").strip()
        actual_label = normalize_label(row.get(label_column))
        if not flow_id or not actual_label:
            continue

        predicted_label = predictions.get(flow_id)
        if predicted_label is None:
            missing_predictions += 1
            predicted_label = "Unknown"

        pairs.append((actual_label, predicted_label))

    return pairs, missing_predictions


def compute_accuracy(pairs):
    if not pairs:
        return 0.0
    correct = sum(1 for actual, predicted in pairs if actual == predicted)
    return correct / len(pairs)


def compute_confusion_matrix(pairs, labels):
    matrix = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    for actual, predicted in pairs:
        matrix[actual][predicted] += 1
    return matrix


def compute_per_class_metrics(pairs, labels):
    metrics = {}
    for label in labels:
        true_positive = sum(1 for actual, predicted in pairs if actual == label and predicted == label)
        false_positive = sum(1 for actual, predicted in pairs if actual != label and predicted == label)
        false_negative = sum(1 for actual, predicted in pairs if actual == label and predicted != label)

        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        metrics[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": sum(1 for actual, _ in pairs if actual == label),
        }

    return metrics


def print_summary(total_labels, matched_pairs, missing_predictions, accuracy):
    print("Evaluation Summary")
    print("------------------")
    print(f"Labeled flows:        {total_labels}")
    print(f"Evaluated flows:      {matched_pairs}")
    print(f"Missing predictions:  {missing_predictions}")
    print(f"Accuracy:             {accuracy:.4f}")


def print_per_class_metrics(metrics, labels):
    print("\nPer-class metrics")
    print("-----------------")
    class_width = max(len("Class"), *(len(label) for label in labels))
    print(
        f"{'Class':<{class_width}} "
        f"{'Precision':>10} "
        f"{'Recall':>10} "
        f"{'F1':>10} "
        f"{'Support':>8}"
    )
    print(
        f"{'-' * class_width} "
        f"{'-' * 10} "
        f"{'-' * 10} "
        f"{'-' * 10} "
        f"{'-' * 8}"
    )
    for label in labels:
        values = metrics[label]
        print(
            f"{label:<{class_width}} "
            f"{values['precision']:>10.4f} "
            f"{values['recall']:>10.4f} "
            f"{values['f1']:>10.4f} "
            f"{values['support']:>8}"
        )


def print_confusion_matrix(matrix, labels):
    print("\nConfusion matrix")
    print("----------------")

    cell_width = max(
        8,
        max(len(label) for label in labels),
        max(len(str(matrix[actual][predicted])) for actual in labels for predicted in labels),
    ) + 2

    header = "actual\\pred".ljust(cell_width) + "".join(label.rjust(cell_width) for label in labels)
    print(header)
    for actual in labels:
        row = actual.ljust(cell_width)
        row += "".join(str(matrix[actual][predicted]).rjust(cell_width) for predicted in labels)
        print(row)


def main():
    args = parse_args()

    try:
        pred_fieldnames, pred_rows = read_csv_rows(args.pred)
        if "flow_id" not in pred_fieldnames or "predicted_app" not in pred_fieldnames:
            raise ValueError("predictions.csv must contain flow_id and predicted_app columns")

        label_fieldnames, label_rows = read_csv_rows(args.labels)
        if "flow_id" not in label_fieldnames:
            raise ValueError("labels.csv must contain a flow_id column")

        label_column = detect_label_column(label_fieldnames)
        predictions = build_prediction_map(pred_rows)
        pairs, missing_predictions = build_pairs(predictions, label_rows, label_column)

        if not pairs:
            raise ValueError("No comparable labeled flows were found")

        labels = sorted({actual for actual, _ in pairs} | {predicted for _, predicted in pairs})
        accuracy = compute_accuracy(pairs)
        metrics = compute_per_class_metrics(pairs, labels)
        confusion = compute_confusion_matrix(pairs, labels)

        print_summary(len(label_rows), len(pairs), missing_predictions, accuracy)
        print_per_class_metrics(metrics, labels)
        print_confusion_matrix(confusion, labels)
        return 0
    except (OSError, ValueError, csv.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
