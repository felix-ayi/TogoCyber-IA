import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
import pandas as pd

from backend.app.api.v1.routes.network import analyze_network
from backend.app.schemas.network import NetworkAnalysisRequest
from ml.common.preprocessing import NETWORK_FEATURES, network_features_from_mapping
from ml.network.preprocessing import load_network_dataset
from ml.network.train import candidates


class NetworkTests(unittest.TestCase):
    def test_daily_cic_csv_directory_is_loaded_and_headers_trimmed(self):
        row = {
            " Flow Duration": 1_000_000,
            " Total Length of Fwd Packets": 20,
            " Total Length of Bwd Packets": 10,
            " Total Fwd Packets": 2,
            " Total Backward Packets": 1,
            " Source Port": 50000,
            " Destination Port": 443,
            " Protocol": 6,
            " Flow Packets/s": 3,
            " Label": "BENIGN",
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            pd.DataFrame([row, {**row, " Label": "DoS Hulk"}]).to_csv(directory / "Monday.csv", index=False)
            pd.DataFrame([{**row, " Label": "BENIGN"}]).to_csv(directory / "Tuesday.csv", index=False)
            features, labels = load_network_dataset(directory, "cic")
        self.assertEqual(len(features), 3)
        self.assertEqual(labels.tolist(), [0, 1, 0])
        self.assertEqual(features["duration"].tolist(), [1.0, 1.0, 1.0])

    def test_two_required_network_classifiers_are_configured(self):
        self.assertEqual(set(candidates(seed=42)), {"random_forest", "xgboost"})

    def test_unsw_cleaned_train_and_test_csvs_load_without_optional_ports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = [
                {"dur": 0.2, "proto": "tcp", "spkts": 4, "dpkts": 2, "sbytes": 100, "dbytes": 50, "rate": 3.0, "label": 0},
                {"dur": 0.7, "proto": "udp", "spkts": 9, "dpkts": 8, "sbytes": 800, "dbytes": 600, "rate": 8.0, "label": 1},
            ]
            path = root / "train.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            features, labels = load_network_dataset(path, "unsw")
        self.assertEqual(len(features), 2)
        self.assertEqual(labels.tolist(), [0, 1])
        self.assertEqual(features["src_port"].tolist(), [0.0, 0.0])

    def test_canonical_schema_accepts_exact_feature_set(self):
        values = {name: 1 for name in NETWORK_FEATURES}
        self.assertEqual(tuple(network_features_from_mapping(values).columns), NETWORK_FEATURES)

    def test_unknown_or_missing_features_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing features"):
            network_features_from_mapping({})
        with self.assertRaisesRegex(ValueError, "unknown features"):
            network_features_from_mapping({**{name: 1 for name in NETWORK_FEATURES}, "unexpected": 1})

    def test_non_finite_values_are_rejected(self):
        values = {name: 1 for name in NETWORK_FEATURES}
        values["duration"] = float("inf")
        with self.assertRaisesRegex(ValueError, "finite"):
            network_features_from_mapping(values)

    def test_missing_trained_artifact_returns_service_unavailable(self):
        values = {name: 0 for name in NETWORK_FEATURES}
        with patch("backend.app.api.v1.routes.network.network_analysis", side_effect=FileNotFoundError("Le modèle n'est pas entraîné")):
            with self.assertRaises(HTTPException) as error:
                analyze_network(NetworkAnalysisRequest(features=values), user={"id": 1})
        self.assertEqual(error.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()