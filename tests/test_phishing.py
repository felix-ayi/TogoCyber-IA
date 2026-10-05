import unittest
import tempfile
from pathlib import Path

from fastapi import HTTPException

from backend.app.api.v1.routes.phishing import analyze_phishing
from backend.app.schemas.phishing import PhishingAnalysisRequest
from ml.phishing.preprocessing import load_phishing_dataset, prepare_training_corpus
from ml.phishing.train import candidates


class PhishingTests(unittest.TestCase):
    def test_two_required_text_classifiers_are_configured(self):
        self.assertEqual(set(candidates(seed=42)), {"logistic_regression", "multinomial_nb"})

    def test_whitespace_only_text_is_rejected(self):
        with self.assertRaises(HTTPException) as error:
            analyze_phishing(PhishingAnalysisRequest(text="   "))
        self.assertEqual(error.exception.status_code, 422)

    def test_dataset_requires_both_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "messages.csv"
            path.write_text("text,label\nA legitimate notice,legitimate\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "both legitimate and phishing"):
                load_phishing_dataset(path)

    def test_public_email_source_columns_and_labels_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.csv"
            path.write_text(
                'Email Text,Email Type\n"Please review invoice",Phishing Email\n"Monthly newsletter",Safe Email\n',
                encoding="utf-8",
            )
            texts, labels = load_phishing_dataset(path)
        self.assertEqual(texts.tolist(), ["Please review invoice", "Monthly newsletter"])
        self.assertEqual(labels.tolist(), [1, 0])

    def test_local_corpus_merge_requires_consent_and_fifty_examples(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public.csv"
            local = root / "local.csv"
            output = root / "combined.csv"
            public.write_text("text,label\nsafe message,legitimate\nbad message,phishing\n", encoding="utf-8")
            local.write_text(
                "text,label,source,consent,language_group\n"
                "exemple,phishing,annotateur,false,togolese_french\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "50–100"):
                prepare_training_corpus(public, local, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()