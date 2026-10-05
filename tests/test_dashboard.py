import unittest

from frontend.views.home import _comparison_rows


class DashboardTests(unittest.TestCase):
    def test_comparison_rows_show_validation_test_and_selected_model(self):
        rows = _comparison_rows({
            "algorithm": "xgboost",
            "comparison_metrics": {
                "random_forest": {
                    "validation_f1": 0.93,
                    "held_out_test": {
                        "f1": 0.92,
                        "precision": 0.97,
                        "recall": 0.88,
                        "roc_auc": 0.98,
                    },
                },
                "xgboost": {
                    "validation_f1": 0.94,
                    "held_out_test": {
                        "f1": 0.91,
                        "precision": 0.98,
                        "recall": 0.87,
                        "roc_auc": 0.99,
                    },
                },
            },
        })

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["Algorithme"], "Random Forest")
        self.assertEqual(rows[1]["F1 validation"], "94.0%")
        self.assertEqual(rows[1]["ROC-AUC test"], "99.0%")
        self.assertEqual([row["Modèle retenu"] for row in rows], ["Non", "Oui"])

    def test_missing_comparison_metrics_are_shown_as_unavailable(self):
        rows = _comparison_rows({
            "algorithm": "multinomial_nb",
            "comparison_metrics": {
                "multinomial_nb": {"validation_f1": None, "held_out_test": None},
            },
        })

        self.assertEqual(rows[0]["F1 validation"], "—")
        self.assertEqual(rows[0]["F1 test"], "—")
        self.assertEqual(rows[0]["Modèle retenu"], "Oui")


if __name__ == "__main__":
    unittest.main()
