import unittest

import pandas as pd

from backend.app.core.security import confidence_level
from ml.common.metrics import binary_metrics
from ml.common.preprocessing import NETWORK_FEATURES, binary_labels, canonical_network_frame, network_features_from_mapping


class MLContractTests(unittest.TestCase):
    def test_network_feature_order_and_finite_validation(self):
        values = {name: 1 for name in NETWORK_FEATURES}
        self.assertEqual(tuple(network_features_from_mapping(values).columns), NETWORK_FEATURES)
        values["duration"] = float("nan")
        with self.assertRaisesRegex(ValueError, "finite"):
            network_features_from_mapping(values)

    def test_cic_attack_names_are_positive(self):
        values = binary_labels(pd.Series(["BENIGN", "DoS Hulk", "PortScan"]), non_benign_is_positive=True)
        self.assertEqual(values.tolist(), [0, 1, 1])

    def test_cic_headers_with_leading_spaces_and_duration_conversion(self):
        columns = {
            " Flow Duration": [2_000_000],
            " Total Length of Fwd Packets": [150],
            " Total Length of Bwd Packets": [50],
            " Total Fwd Packets": [3],
            " Total Backward Packets": [2],
            " Source Port": [1234],
            " Destination Port": [443],
            " Protocol": [6],
            " Flow Packets/s": [2.5],
        }
        frame = canonical_network_frame(pd.DataFrame(columns), "cic")
        self.assertEqual(frame.iloc[0]["duration"], 2.0)
        self.assertEqual(tuple(frame.columns), NETWORK_FEATURES)

    def test_unsw_cleaned_source_without_ports_uses_documented_zero_placeholders(self):
        source = pd.DataFrame({
            "dur": [0.4], "proto": ["tcp"], "spkts": [5], "dpkts": [4],
            "sbytes": [200], "dbytes": [150], "rate": [9.0],
        })
        frame = canonical_network_frame(source, "unsw")
        self.assertEqual(frame.iloc[0]["protocol_number"], 6.0)
        self.assertEqual(frame.iloc[0]["src_port"], 0.0)
        self.assertEqual(frame.iloc[0]["dst_port"], 0.0)

    def test_binary_classes_are_normalized(self):
        values = binary_labels(pd.Series(["benign", "phishing", "0", "1"]))
        self.assertEqual(values.tolist(), [0, 1, 0, 1])

    def test_confidence_levels_have_exact_boundaries(self):
        self.assertEqual([confidence_level(value) for value in (0.59, 0.6, 0.8)], ["low", "medium", "high"])

    def test_invalid_confidence_values_are_rejected(self):
        with self.assertRaises(ValueError):
            confidence_level(float("nan"))
        with self.assertRaises(ValueError):
            confidence_level(True)

    def test_metrics_include_imbalance_sensitive_geometric_mean(self):
        report = binary_metrics([0, 1, 0, 1], [0, 1, 1, 1], [0.1, 0.9, 0.7, 0.8])
        self.assertAlmostEqual(report["geometric_mean"], 2 ** -0.5)


if __name__ == "__main__":
    unittest.main()
