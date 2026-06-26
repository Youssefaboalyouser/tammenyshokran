# """
# nlp_model.py
# ------------
# NLP spam detection using mrm8488/bert-tiny-finetuned-sms-spam-detection.
# Includes inference, fine-tuning on custom CSV, and evaluation.

# CSV format expected:
#     "message text",1
#     "another message",0
#     (1 = spam, 0 = ham/legitimate)
# """

# import os
# import csv
# import json
# from pathlib import Path
# from typing import Optional

# import chardet

# # Lazy imports — only loaded when needed so the server starts fast
# # even if torch/transformers are slow to import.
# _pipeline = None
# _FINE_TUNED_PATH = Path(__file__).parent.parent / "data" / "nlp_model_v5"
# _CONTINUE_FROM_PATH = _FINE_TUNED_PATH
# _NEW_MODEL_PATH = Path(__file__).parent.parent / "data" / "nlp_model_v5"
# _BASE_MODEL = "mrm8488/bert-tiny-finetuned-sms-spam-detection"


# def _get_pipeline():
#     """Return cached inference pipeline, loading it on first call."""
#     global _pipeline
#     if _pipeline is not None:
#         return _pipeline

#     from transformers import pipeline as hf_pipeline

#     # Prefer the newest local fine-tuned model if it exists.
#     if _NEW_MODEL_PATH.exists():
#         model_path = str(_NEW_MODEL_PATH)
#     elif _FINE_TUNED_PATH.exists():
#         model_path = str(_FINE_TUNED_PATH)
#     else:
#         model_path = _BASE_MODEL
#     print(f"[NLP] Loading model from: {model_path}")

#     _pipeline = hf_pipeline(
#         "text-classification",
#         model=model_path,
#         tokenizer=model_path,
#         truncation=True,
#         max_length=512,
#     )
#     return _pipeline


# # ── Public inference API ─────────────────────────────────────────────────────

# def predict_spam(text: str) -> dict:
#     """
#     Classify a text message as SPAM or HAM.

#     Returns:
#         {
#             "label": "SPAM" | "HAM",
#             "score": float (0.0–1.0 confidence),
#             "is_spam": bool
#         }
#     """
#     if not text or not text.strip():
#         return {"label": "HAM", "score": 1.0, "is_spam": False}

#     pipe = _get_pipeline()
#     result = pipe(text[:512])[0]  # truncate just in case

#     # Model labels: "LABEL_1" = spam, "LABEL_0" = ham
#     # Some fine-tuned variants use "SPAM"/"HAM" directly
#     raw_label: str = result["label"].upper()
#     score: float = float(result["score"])

#     if raw_label in ("LABEL_1", "SPAM"):
#         is_spam = True
#         label = "SPAM"
#         confidence = score
#     elif raw_label in ("LABEL_0", "HAM"):
#         is_spam = False
#         label = "HAM"
#         confidence = score
#     else:
#         # Fallback — treat unknown label conservatively
#         is_spam = score > 0.5
#         label = "SPAM" if is_spam else "HAM"
#         confidence = score

#     return {"label": label, "score": round(confidence, 4), "is_spam": is_spam}


# # ── Fine-tuning ──────────────────────────────────────────────────────────────

# def fine_tune(
#     csv_path: str,
#     output_dir: Optional[str] = None,
#     epochs: int = 3,
#     batch_size: int = 16,
#     max_length: int = 128,
#     learning_rate: float = 2e-5,
#     test_split: float = 0.2,
# ):
#     """
#     Fine-tune the base model on a custom CSV dataset.

#     CSV format (no header):
#         "message text",1
#         "another message",0

#     Args:
#         csv_path:      Path to your CSV file.
#         output_dir:    Where to save the fine-tuned model.
#                        Defaults to app/data/nlp_model_v3/.
#         epochs:        Number of training epochs.
#         batch_size:    Training batch size.
#         max_length:    Max token length.
#         learning_rate: Adam learning rate.
#         test_split:    Fraction held out for evaluation.
#     """
#     import torch
#     import pandas as pd
#     from sklearn.model_selection import train_test_split
#     from sklearn.metrics import classification_report
#     from transformers import (
#         AutoTokenizer,
#         AutoModelForSequenceClassification,
#         TrainingArguments,
#         Trainer,
#         DataCollatorWithPadding,
#     )
#     from datasets import Dataset

#     output_dir = output_dir or str(_NEW_MODEL_PATH)
#     Path(output_dir).mkdir(parents=True, exist_ok=True)

#     # ── Load CSV ─────────────────────────────────────────────────────────────
#     print("[Fine-tune] Loading dataset...")
#     rows = []
#     with open(csv_path, "rb") as f:
#         raw = f.read(10000)
#         encoding = chardet.detect(raw)["encoding"]
#     with open(csv_path, newline="", encoding=encoding,errors="replace") as f:
#         reader = csv.reader(f)
#         for row in reader:
#             if len(row) < 2:
#                 continue
#             text = row[0].strip().strip('"')
#             try:
#                 label = int(row[-1].strip())
#             except ValueError:
#                 continue
#             if label not in (0, 1):
#                 continue
#             rows.append({"text": text, "label": label})

#     if len(rows) < 10:
#         raise ValueError(f"Dataset too small: only {len(rows)} valid rows found.")

#     print(f"[Fine-tune] Loaded {len(rows)} samples.")
#     df = pd.DataFrame(rows)
#     spam_count = df["label"].sum()
#     ham_count = len(df) - spam_count
#     print(f"[Fine-tune] Distribution → SPAM: {spam_count}, HAM: {ham_count}")

#     # ── Train / test split ───────────────────────────────────────────────────
#     train_df, test_df = train_test_split(
#         df, test_size=test_split, random_state=42, stratify=df["label"]
#     )
#     train_ds = Dataset.from_pandas(train_df.reset_index(drop=True))
#     test_ds = Dataset.from_pandas(test_df.reset_index(drop=True))

#     # ── Tokenizer ────────────────────────────────────────────────────────────
#     # Always start fine-tuning from the base model instead of any existing local checkpoint.
#     # tokenizer_source = str(_CONTINUE_FROM_PATH) if _CONTINUE_FROM_PATH.exists() else _BASE_MODEL
#     tokenizer_source = str(_BASE_MODEL)
#     print(f"[Fine-tune] Loading tokenizer from {tokenizer_source}...")
#     tokenizer = AutoTokenizer.from_pretrained(tokenizer_source)

#     def tokenize(batch):
#         return tokenizer(
#             batch["text"],
#             truncation=True,
#             padding=False,
#             max_length=max_length,
#         )

#     train_ds = train_ds.map(tokenize, batched=True)
#     test_ds = test_ds.map(tokenize, batched=True)

#     # ── Model ────────────────────────────────────────────────────────────────
#     # Always start fine-tuning from the base model instead of any existing local checkpoint.
#     # model_source = str(_CONTINUE_FROM_PATH) if _CONTINUE_FROM_PATH.exists() else _BASE_MODEL
#     model_source = str(_BASE_MODEL)
#     print(f"[Fine-tune] Loading model from {model_source}...")
#     model = AutoModelForSequenceClassification.from_pretrained(
#         model_source, num_labels=2, ignore_mismatched_sizes=True
#     )

#     # ── Training ─────────────────────────────────────────────────────────────
#     training_args = TrainingArguments(
#         output_dir=output_dir,
#         num_train_epochs=epochs,
#         per_device_train_batch_size=batch_size,
#         per_device_eval_batch_size=batch_size,
#         learning_rate=learning_rate,
#         weight_decay=0.01,
#         eval_strategy="epoch",
#         save_strategy="epoch",
#         load_best_model_at_end=True,
#         metric_for_best_model="eval_loss",
#         logging_steps=50,
#         fp16=torch.cuda.is_available(),
#         report_to="none",
#     )

#     data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

#     trainer = Trainer(
#         model=model,
#         args=training_args,
#         train_dataset=train_ds,
#         eval_dataset=test_ds,
#         data_collator=data_collator,
#     )

#     print("[Fine-tune] Training started...")
#     trainer.train()
#     print("[Fine-tune] Training complete.")

#     # ── Save ─────────────────────────────────────────────────────────────────
#     trainer.save_model(output_dir)
#     tokenizer.save_pretrained(output_dir)
#     print(f"[Fine-tune] Model saved to {output_dir}")

#     # ── Evaluation ───────────────────────────────────────────────────────────
#     print("[Fine-tune] Running evaluation...")
#     predictions = trainer.predict(test_ds)
#     import numpy as np
#     preds = np.argmax(predictions.predictions, axis=1)
#     labels = predictions.label_ids

#     report = classification_report(labels, preds, target_names=["HAM", "SPAM"])
#     print("\n── Classification Report ──")
#     print(report)

#     # Save report
#     report_path = Path(output_dir) / "eval_report.txt"
#     report_path.write_text(report, encoding="utf-8")
#     print(f"[Fine-tune] Report saved to {report_path}")

#     # Reset cached pipeline so next call loads the new model
#     global _pipeline
#     _pipeline = None

#     return {"status": "done", "output_dir": output_dir, "samples": len(rows)}


# # ── CLI entry point ──────────────────────────────────────────────────────────
# # Run with: python -m app.services.nlp_model --csv path/to/data.csv

# if __name__ == "__main__":
#     import argparse

#     parser = argparse.ArgumentParser(description="Fine-tune spam detection model")
#     parser.add_argument("--csv", required=True, help="Path to training CSV")
#     parser.add_argument("--output", default=None, help="Output directory for model")
#     parser.add_argument("--epochs", type=int, default=3)
#     parser.add_argument("--batch", type=int, default=16)
#     parser.add_argument("--lr", type=float, default=2e-5)
#     args = parser.parse_args()

#     result = fine_tune(
#         csv_path=args.csv,
#         output_dir=args.output,
#         epochs=args.epochs,
#         batch_size=args.batch,
#         learning_rate=args.lr,
#     )
#     print(json.dumps(result, indent=2))
# ===========================================================================================================================================================
"""
nlp_model.py — Fixed for Tamenny
Key fixes:
  1. Confidence threshold (default 0.70) prevents low-confidence spam flags
  2. Class-weighted loss during fine-tuning to handle imbalanced data
  3. Oversampling minority class option
  4. Proper label2id/id2label mapping to prevent label confusion
  5. Text truncation strategy for long emails (take first + last chunk)
"""

import os
import csv
import json
from pathlib import Path
from typing import Optional

import chardet

_pipeline = None
_FINE_TUNED_PATH = Path(__file__).parent.parent / "data" / "nlp_model_v7"
_NEW_MODEL_PATH = _FINE_TUNED_PATH
_BASE_MODEL = "mrm8488/bert-tiny-finetuned-sms-spam-detection"

# ── Confidence threshold ──────────────────────────────────────────────────────
# Only flag as SPAM if confidence >= this value.
# Raise it (e.g. 0.80) to reduce false positives.
SPAM_CONFIDENCE_THRESHOLD = 0.90


def _smart_truncate(text: str, max_chars: int = 1000) -> str:
    """
    For long emails, take first 700 chars + last 300 chars.
    This captures subject/greeting AND footer patterns better than
    naive head truncation.
    """
    if len(text) <= max_chars:
        return text
    head = text[:700]
    tail = text[-300:]
    return head + " [...] " + tail


def _get_pipeline():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    from transformers import pipeline as hf_pipeline
    model_path = str(_NEW_MODEL_PATH) if _NEW_MODEL_PATH.exists() else _BASE_MODEL
    print(f"[NLP] Loading model from: {model_path}")
    _pipeline = hf_pipeline(
        "text-classification",
        model=model_path,
        tokenizer=model_path,
        truncation=True,
        max_length=512,
    )
    return _pipeline


def predict_spam(text: str, threshold: float = SPAM_CONFIDENCE_THRESHOLD) -> dict:
    """
    Classify text as SPAM or HAM with confidence thresholding.

    Returns:
        {
            "label": "SPAM" | "HAM",
            "score": float,
            "is_spam": bool,
            "raw_label": str   # model's actual output label
        }
    """
    if not text or not text.strip():
        return {"label": "HAM", "score": 1.0, "is_spam": False, "raw_label": "HAM"}

    text = _smart_truncate(text)
    pipe = _get_pipeline()
    result = pipe(text)[0]

    raw_label: str = result["label"].upper()
    score: float = float(result["score"])

    if raw_label in ("LABEL_1", "SPAM"):
        # Only mark spam if confidence clears the threshold
        is_spam = score >= threshold
        label = "SPAM" if is_spam else "HAM"
        confidence = score
    elif raw_label in ("LABEL_0", "HAM"):
        is_spam = False
        label = "HAM"
        confidence = score
    else:
        is_spam = score >= threshold
        label = "SPAM" if is_spam else "HAM"
        confidence = score

    return {
        "label": label,
        "score": round(confidence, 4),
        "is_spam": is_spam,
        "raw_label": raw_label,
    }


def fine_tune(
    csv_path: str,
    output_dir: Optional[str] = None,
    epochs: int = 4,
    batch_size: int = 16,
    max_length: int = 128,
    learning_rate: float = 2e-5,
    test_split: float = 0.2,
    use_class_weights: bool = True,
    oversample_minority: bool = True,
):
    import torch
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    from sklearn.utils import resample
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
        DataCollatorWithPadding,
    )
    from datasets import Dataset

    output_dir = output_dir or str(_NEW_MODEL_PATH)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # ── Load CSV ──────────────────────────────────────────────────────────────
    print("[Fine-tune] Loading dataset...")
    rows = []
    with open(csv_path, "rb") as f:
        raw = f.read(10000)
        encoding = chardet.detect(raw)["encoding"] or "utf-8"
    with open(csv_path, newline="", encoding=encoding, errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            text = row[0].strip().strip('"')
            try:
                label = int(row[-1].strip())
            except ValueError:
                continue
            if label not in (0, 1):
                continue
            rows.append({"text": text, "label": label})

    if len(rows) < 10:
        raise ValueError(f"Dataset too small: only {len(rows)} valid rows found.")

    df = pd.DataFrame(rows)
    spam_count = int(df["label"].sum())
    ham_count = len(df) - spam_count
    print(f"[Fine-tune] Loaded {len(rows)} samples → SPAM: {spam_count}, HAM: {ham_count}")

    # ── Fix class imbalance via oversampling ──────────────────────────────────
    if oversample_minority:
        df_spam = df[df["label"] == 1]
        df_ham = df[df["label"] == 0]
        if spam_count < ham_count:
            df_spam = resample(df_spam, replace=True, n_samples=ham_count, random_state=42)
        elif ham_count < spam_count:
            df_ham = resample(df_ham, replace=True, n_samples=spam_count, random_state=42)
        df = pd.concat([df_spam, df_ham]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"[Fine-tune] After oversampling: {len(df)} samples (balanced)")

    # ── Train / test split ────────────────────────────────────────────────────
    train_df, test_df = train_test_split(
        df, test_size=test_split, random_state=42, stratify=df["label"]
    )
    train_ds = Dataset.from_pandas(train_df.reset_index(drop=True))
    test_ds = Dataset.from_pandas(test_df.reset_index(drop=True))

    # ── Tokenizer & Model ─────────────────────────────────────────────────────
    print(f"[Fine-tune] Loading tokenizer and model from {_BASE_MODEL}...")
    tokenizer = AutoTokenizer.from_pretrained(_BASE_MODEL)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, padding=False, max_length=max_length)

    train_ds = train_ds.map(tokenize, batched=True)
    test_ds = test_ds.map(tokenize, batched=True)

    # Explicit label mapping prevents LABEL_0/LABEL_1 confusion
    label2id = {"HAM": 0, "SPAM": 1}
    id2label = {0: "HAM", 1: "SPAM"}

    model = AutoModelForSequenceClassification.from_pretrained(
        _BASE_MODEL,
        num_labels=2,
        ignore_mismatched_sizes=True,
        label2id=label2id,
        id2label=id2label,
    )

    # ── Class-weighted loss ───────────────────────────────────────────────────
    # This is the most important fix for imbalanced data.
    class WeightedTrainer(Trainer):
        def __init__(self, class_weights=None, **kwargs):
            super().__init__(**kwargs)
            self.class_weights = class_weights

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits
            if self.class_weights is not None:
                weights = torch.tensor(self.class_weights, dtype=torch.float).to(logits.device)
                loss_fn = torch.nn.CrossEntropyLoss(weight=weights)
            else:
                loss_fn = torch.nn.CrossEntropyLoss()
            loss = loss_fn(logits, labels)
            return (loss, outputs) if return_outputs else loss

    # Compute weights: higher weight for the minority class
    total = len(train_df)
    w_ham = total / (2 * ham_count) if ham_count > 0 else 1.0
    w_spam = total / (2 * spam_count) if spam_count > 0 else 1.0
    class_weights = [w_ham, w_spam] if use_class_weights else None
    print(f"[Fine-tune] Class weights → HAM: {w_ham:.3f}, SPAM: {w_spam:.3f}")

    # ── Training ──────────────────────────────────────────────────────────────
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=50,
        fp16=torch.cuda.is_available(),
        report_to="none",
        warmup_ratio=0.1,  # Helps with early overfitting
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    trainer = WeightedTrainer(
        class_weights=class_weights,
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=test_ds,
        data_collator=data_collator,
    )

    print("[Fine-tune] Training started...")
    trainer.train()
    print("[Fine-tune] Training complete.")

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"[Fine-tune] Model saved to {output_dir}")

    # ── Evaluation ────────────────────────────────────────────────────────────
    predictions = trainer.predict(test_ds)
    preds = np.argmax(predictions.predictions, axis=1)
    labels = predictions.label_ids
    report = classification_report(labels, preds, target_names=["HAM", "SPAM"])
    print("\n── Classification Report ──")
    print(report)

    report_path = Path(output_dir) / "eval_report.txt"
    report_path.write_text(report, encoding="utf-8")

    global _pipeline
    _pipeline = None

    return {"status": "done", "output_dir": output_dir, "samples": len(rows)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fine-tune spam detection model")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--no-class-weights", action="store_true")
    parser.add_argument("--no-oversample", action="store_true")
    args = parser.parse_args()

    result = fine_tune(
        csv_path=args.csv,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch,
        learning_rate=args.lr,
        use_class_weights=not args.no_class_weights,
        oversample_minority=not args.no_oversample,
    )
    print(json.dumps(result, indent=2))
