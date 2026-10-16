import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from leak_harness import SURFACES, fragments, scan

CANARY = "mos_canary_93a82bc19d:large_unique_first_half_xyz_large_unique_second_half_abc"


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("kind,fragment", [p for p in fragments(CANARY) if p[0] != "secret_window"])
def test_each_surface_and_fragment_has_a_red_positive_control(surface, kind, fragment):
    findings = scan({surface:{"captured":fragment}},[CANARY])
    assert any(f.surface==surface and f.kind==kind for f in findings)
    assert fragment not in repr(findings)


@pytest.mark.parametrize("surface",SURFACES)
def test_clean_surface_is_green(surface):
    assert scan({surface:{"captured":"ordinary saved context"}},[CANARY]) == ()


@pytest.mark.parametrize("surface",SURFACES)
def test_mid_secret_window_is_red(surface):
    secret=CANARY.split(":",1)[1]
    assert scan({surface:secret[11:23]},[CANARY])


def test_public_prefix_allowed_but_secret_forbidden():
    prefix,secret=CANARY.split(":",1)
    assert not scan({"tool_arguments_results":"Client ID: "+prefix},[CANARY])
    assert scan({"tool_arguments_results":"Client ID: "+prefix+" " + secret},[CANARY])
