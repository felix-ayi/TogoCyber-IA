import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from backend.app.api.v1.routes.phishing import analyze_phishing
from backend.app.schemas.phishing import PhishingAnalysisRequest, PhishingAnalysisResponse
from backend.app.services.phishing_service import AnalysisCapacityExceeded, analyze_phishing as analyze_phishing_service
from ml.phishing.explain import LIME_NUM_SAMPLES, PHISHING_EXPLANATION_MAX_CHARS, explain_phishing
from ml.phishing.preprocessing import load_phishing_dataset, prepare_training_corpus
from ml.phishing.train import candidates


class PhishingTests(unittest.TestCase):
    def test_two_required_text_classifiers_are_configured(self):
        self.assertEqual(set(candidates(seed=42)), {"logistic_regression", "multinomial_nb"})

    def test_whitespace_only_text_is_rejected(self):
        with self.assertRaises(HTTPException) as error:
            analyze_phishing(PhishingAnalysisRequest(text="   "))
        self.assertEqual(error.exception.status_code, 422)

    def test_request_length_boundary_is_enforced(self):
        self.assertEqual(len(PhishingAnalysisRequest(text="x" * 20_000).text), 20_000)
        with self.assertRaises(ValidationError):
            PhishingAnalysisRequest(text="x" * 20_001)

    def test_explanation_has_explicit_sample_and_text_bounds(self):
        model = SimpleNamespace(predict_proba=lambda values: [[0.5, 0.5]])
        explanation = SimpleNamespace(as_list=lambda label: [("signal", 0.2)])
        with (
            patch("ml.phishing.explain.load_model", return_value=model),
            patch("ml.phishing.explain.LimeTextExplainer") as explainer_factory,
        ):
            explainer_factory.return_value.explain_instance.return_value = explanation
            result = explain_phishing("x" * (PHISHING_EXPLANATION_MAX_CHARS + 500))

        call = explainer_factory.return_value.explain_instance
        self.assertEqual(len(call.call_args.args[0]), PHISHING_EXPLANATION_MAX_CHARS)
        self.assertEqual(call.call_args.kwargs["num_samples"], LIME_NUM_SAMPLES)
        self.assertEqual(result, [{"term": "signal", "contribution": 0.2}])

    def test_excess_concurrent_analyses_are_rejected_and_route_returns_429(self):
        from backend.app.services import phishing_service

        acquired_count = 0
        try:
            for _ in range(phishing_service.MAX_CONCURRENT_PHISHING_ANALYSES):
                if not phishing_service._analysis_slots.acquire(blocking=False):
                    break
                acquired_count += 1
            self.assertEqual(acquired_count, phishing_service.MAX_CONCURRENT_PHISHING_ANALYSES)

            with patch("backend.app.services.phishing_service.predict_phishing") as predict:
                with self.assertRaises(AnalysisCapacityExceeded):
                    analyze_phishing_service("message")
                predict.assert_not_called()

            with patch(
                "backend.app.api.v1.routes.phishing.phishing_analysis",
                side_effect=AnalysisCapacityExceeded("busy"),
            ):
                with self.assertRaises(HTTPException) as error:
                    analyze_phishing(PhishingAnalysisRequest(text="message"))
            self.assertEqual(error.exception.status_code, 429)
        finally:
            for _ in range(acquired_count):
                phishing_service._analysis_slots.release()

    def test_analysis_reports_when_explanation_uses_only_excerpt(self):
        prediction = {
            "prediction": "phishing",
            "phishing_probability": 0.9,
            "confidence": 0.9,
            "confidence_level": "high",
        }
        with (
            patch("backend.app.services.phishing_service.predict_phishing", return_value=prediction),
            patch("backend.app.services.phishing_service.explain_phishing", return_value=[]),
            patch("backend.app.services.phishing_service.record_event", return_value=1),
        ):
            result = analyze_phishing_service("x" * (PHISHING_EXPLANATION_MAX_CHARS + 1))

        self.assertTrue(result["explanation_truncated"])
        self.assertTrue(PhishingAnalysisResponse.model_validate(result).explanation_truncated)

    def test_analysis_slot_is_released_when_inference_fails(self):
        from backend.app.services import phishing_service

        with patch(
            "backend.app.services.phishing_service.predict_phishing",
            side_effect=RuntimeError("inference failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "inference failed"):
                analyze_phishing_service("message")

        acquired_count = 0
        try:
            for _ in range(phishing_service.MAX_CONCURRENT_PHISHING_ANALYSES):
                if not phishing_service._analysis_slots.acquire(blocking=False):
                    break
                acquired_count += 1
            self.assertEqual(acquired_count, phishing_service.MAX_CONCURRENT_PHISHING_ANALYSES)
        finally:
            for _ in range(acquired_count):
                phishing_service._analysis_slots.release()

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