import json
import typing

import pytest

from casebook import paths
from casebook.assess import MODEL, AssessmentError, assess
from casebook.enrich import Context, enrich
from casebook.models import load_alert
from casebook.records import ACTIONS, VERDICTS, Assessment, RecommendedAction
from conftest import SAMPLE_ALERT, FakeClient, fake_response


def _inputs():
    alert = load_alert(SAMPLE_ALERT)
    return alert, enrich(alert, Context.load())


def test_schema_and_model_agree():
    schema = json.loads(paths.OUTPUT_SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["required"]) == set(Assessment.model_fields)
    assert set(schema["properties"]) == set(Assessment.model_fields)
    assert tuple(schema["properties"]["verdict"]["enum"]) == VERDICTS
    action_enum = schema["properties"]["recommended_actions"]["items"]["properties"]["action"]["enum"]
    assert tuple(action_enum) == ACTIONS
    assert typing.get_args(RecommendedAction.model_fields["action"].annotation) == ACTIONS


def test_assess_sends_schema_and_records_call(fake_client):
    assessment, call = assess(*_inputs(), fake_client)
    assert assessment.verdict == "true_positive"

    (kwargs,) = fake_client.calls
    assert kwargs["model"] == MODEL == "claude-sonnet-5-5"
    assert kwargs["output_config"]["format"]["type"] == "json_schema"
    assert kwargs["output_config"]["format"]["schema"]["additionalProperties"] is False
    assert kwargs["fallbacks"] == "default"
    assert "<alert>" in kwargs["messages"][0]["content"]

    assert call.model_served == "claude-sonnet-5-5"
    assert call.user_message == kwargs["messages"][0]["content"]
    assert call.system_prompt == kwargs["system"]
    assert json.loads(call.raw_output)["verdict"] == "true_positive"


def test_refusal_is_an_error():
    client = FakeClient(fake_response(stop_reason="refusal"))
    with pytest.raises(AssessmentError, match="declined"):
        assess(*_inputs(), client)


def test_truncated_output_is_an_error():
    client = FakeClient(fake_response(stop_reason="max_tokens"))
    with pytest.raises(AssessmentError, match="max_tokens"):
        assess(*_inputs(), client)


def test_off_schema_output_is_an_error():
    client = FakeClient(fake_response(text='{"verdict": "probably fine"}'))
    with pytest.raises(AssessmentError, match="schema"):
        assess(*_inputs(), client)


def test_records_fallback_model_when_one_served():
    client = FakeClient(fake_response(model="claude-opus-5-5"))
    _, call = assess(*_inputs(), client)
    assert call.model_requested == "claude-sonnet-5-5"
    assert call.model_served == "claude-opus-5-5"
