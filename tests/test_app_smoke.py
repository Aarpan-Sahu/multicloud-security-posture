"""Renders the whole dashboard headlessly against demo data."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def test_app_renders_with_demo_data():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert at.title[0].value == "Multi-Cloud Security Posture"
    assert len(at.metric) == 5
    labels = [m.label for m in at.metric]
    assert "Posture score" in labels


def test_filters_reduce_findings():
    at = AppTest.from_file(APP, default_timeout=60).run()
    total = int(next(m.value for m in at.metric if m.label == "Open findings"))
    at.toggle[0].set_value(True).run()
    exposed = int(next(m.value for m in at.metric if m.label == "Open findings"))
    assert not at.exception and 0 < exposed < total
