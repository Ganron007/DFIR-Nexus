"""Insider Threat Matrix prompt loader."""

from nexus.langgraph.itm import ITM_URL, itm_prompt_block


def test_itm_prompt_contains_stages_and_url():
    block = itm_prompt_block()
    assert ITM_URL in block
    assert "Motive" in block
    assert "Preparation" in block
    assert "Infringement" in block
    assert "Anti-Forensics" in block
    assert "Data Staging" in block
