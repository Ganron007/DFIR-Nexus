"""A job's registered input is found in its argv even after the flag that carries it (WO-TA item 12).

logfileparser takes /LogFileFile:H:\C\$LogFile, and the H: volume is registered with a sha256. Before this
fix the job never matched that volume, so it had no identity, and a retry re-ran it on every pass. Its second
output folder was then indexed beside the first (CASE-C5B04D31, run RUN-20261011T084105445874Z-tools-b4c9add7).
"""

from __future__ import annotations

from nexus.langgraph import tool_lane
from nexus.langgraph.tool_lane import ToolJob


def _job(argv: list[str]) -> ToolJob:
    return ToolJob(host="windows", tool=argv[0], argv=argv, purpose="test job")


def test_a_path_after_its_flag_identifies_the_registered_volume():
    registered = [("H:\\", "a5e4afda7533")]
    job = _job(["logfileparser", "/LogFileFile:H:\C\$LogFile", "/OutputPath:C:\out"])
    assert tool_lane._evidence_sha_for(job, registered) == "a5e4afda7533"


def test_a_path_after_an_equals_sign_identifies_the_registered_image():
    registered = [("C:\Evidence\rd01-memory.img", "9ab3afa5c871")]
    job = _job(["memprocfs", "--image=C:\Evidence\rd01-memory.img"])
    assert tool_lane._evidence_sha_for(job, registered) == "9ab3afa5c871"


def test_an_output_path_does_not_identify_an_input():
    registered = [("H:\\", "a5e4afda7533")]
    job = _job(["logfileparser", "/OutputPath:C:\out\logfileparser"])
    assert tool_lane._evidence_sha_for(job, registered) == ""
