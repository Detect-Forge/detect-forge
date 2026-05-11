from detect_forge.exit_codes import CLEAN, GATED, RESERVED


def test_clean_is_zero() -> None:
    assert CLEAN == 0


def test_reserved_is_one() -> None:
    assert RESERVED == 1


def test_gated_is_two() -> None:
    assert GATED == 2
