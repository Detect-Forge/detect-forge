"""OpenAI client wrapper, prompt rendering, and structured-output call.

This module owns:
- The OpenAI client lifecycle (constructed on demand with an API key).
- Jinja2 rendering of the diff-proposal prompt from a packaged template.
- The structured-output call (``client.beta.chat.completions.parse``) returning
  a parsed ``DiffProposal`` instance, or ``None`` on refusal / API error.

This module does NOT know about scoring, findings, the cache, or post-receive
validation. Validation lives in a separate concern (callers run it after
``generate_proposal`` returns).
"""

from __future__ import annotations

import logging

import openai
import yaml
from jinja2 import Environment, PackageLoader

from .models import DetectionRule, DiffProposal

log = logging.getLogger(__name__)

OPENAI_API_KEY_ENV = "OPENAI_API_KEY"
"""Environment variable that must be set for proposal generation to fire."""


def _env() -> Environment:
    """Return the Jinja2 environment configured to load prompts from the package."""
    return Environment(
        loader=PackageLoader("detect_forge.stale", "prompts"),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_prompt(
    *,
    rule: DetectionRule,
    original_rule_text: str,
    original_format: str,
    technique_id: str,
    technique_name: str,
    technique_description: str,
    similarity_score: float,
    threshold: float,
    today: str,
) -> str:
    """Render the diff-proposal prompt from the packaged template."""
    template = _env().get_template("diff_proposal.j2")
    return template.render(
        rule=rule,
        original_rule=original_rule_text,
        original_format=original_format,
        technique_id=technique_id,
        technique_name=technique_name,
        technique_description=technique_description,
        similarity_score=similarity_score,
        threshold=threshold,
        today=today,
    )


def generate_proposal(
    *,
    rule: DetectionRule,
    original_rule_text: str,
    original_format: str,
    technique_id: str,
    technique_name: str,
    technique_description: str,
    similarity_score: float,
    threshold: float,
    llm_model: str,
    api_key: str,
    today: str,
) -> DiffProposal | None:
    """Call OpenAI's structured-output API; return a parsed DiffProposal or None.

    Returns ``None`` when:
    - The API call raises any exception (logged at WARNING).
    - The model returned a refusal (no ``parsed`` payload).
    - The model returned a ``parsed`` payload but it failed pydantic validation
      (logged at WARNING).

    Callers must perform format-appropriate validation on
    ``proposal.proposed_rule`` (pySigma for Sigma, ``tomllib`` for Elastic)
    before displaying the result.
    """
    prompt = render_prompt(
        rule=rule,
        original_rule_text=original_rule_text,
        original_format=original_format,
        technique_id=technique_id,
        technique_name=technique_name,
        technique_description=technique_description,
        similarity_score=similarity_score,
        threshold=threshold,
        today=today,
    )

    try:
        client = openai.OpenAI(api_key=api_key)
        completion = client.beta.chat.completions.parse(
            model=llm_model,
            messages=[
                {"role": "user", "content": prompt},
            ],
            response_format=DiffProposal,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("OpenAI proposal call failed: %s", exc)
        return None

    if not completion.choices:
        log.warning("OpenAI returned no choices for proposal request")
        return None

    message = completion.choices[0].message
    if getattr(message, "refusal", None):
        log.warning("OpenAI refused the proposal request: %s", message.refusal)
        return None

    parsed = getattr(message, "parsed", None)
    if parsed is None:
        log.warning("OpenAI returned no parsed payload for proposal request")
        return None

    if not isinstance(parsed, DiffProposal):
        log.warning("OpenAI returned unexpected payload type: %s", type(parsed))
        return None

    return parsed


def validate_proposed_rule(proposed_rule: str, original_format: str) -> bool:
    """Verify the LLM's proposed rule parses correctly for its format.

    Sigma rules are parsed with pySigma. Elastic rules are parsed with
    tomllib + minimum-shape check (`rule.name` must exist). Returns ``True``
    when the proposal is syntactically valid, ``False`` otherwise (with
    DEBUG-level logging of the specific error). Unknown formats reject.
    """
    if original_format == "sigma":
        return _validate_sigma(proposed_rule)
    if original_format == "elastic":
        return _validate_elastic(proposed_rule)
    log.debug("Unknown rule format for validation: %s", original_format)
    return False


def _validate_sigma(yaml_text: str) -> bool:
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        log.debug("Sigma YAML parse failed: %s", exc)
        return False

    if not isinstance(raw, dict):
        log.debug("Sigma YAML is not a mapping at top level")
        return False

    if not raw.get("title"):
        log.debug("Sigma rule has no title — fails pySigma minimum-shape check")
        return False

    # Optional deeper validation via pySigma. Importing here keeps the import
    # cost off the cold path when proposals aren't generated.
    try:
        from sigma.rule import SigmaRule as PySigmaRule

        PySigmaRule.from_yaml(yaml_text)
    except Exception as exc:  # noqa: BLE001
        log.debug("pySigma validation failed: %s", exc)
        return False

    return True


def _validate_elastic(toml_text: str) -> bool:
    import tomllib

    try:
        raw = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        log.debug("Elastic TOML parse failed: %s", exc)
        return False

    rule_section = raw.get("rule")
    if not isinstance(rule_section, dict):
        log.debug("Elastic TOML has no [rule] section")
        return False

    if not rule_section.get("name"):
        log.debug("Elastic rule has no rule.name")
        return False

    return True
