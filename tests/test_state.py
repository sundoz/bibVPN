import os

import pytest

from bibvpn import keys, state as st


def test_reality_keypair_roundtrip():
    private, public = keys.reality_keypair()
    assert len(private) == 43 and len(public) == 43  # 32 bytes, unpadded base64url
    assert keys.public_key_from_private(private) == public


def test_public_key_matches_xray_reference():
    # Reference pair produced by `xray x25519` (Xray 26.9.9).
    assert (
        keys.public_key_from_private("kLEMjNxFMqPK9eU0NuMrlgLYlh_Q7_QPo34B2Z5tflI")
        == "Pf7h53vdFT92TC-fuTUVv187I0L7ZzSfWntRJN8hTm8"
    )


def test_add_node_generates_secrets():
    s = st.State()
    node = s.add_node("fi1", "198.51.100.7", sni="www.example.org")
    assert node.port == 443
    assert len(node.reality.short_ids[0]) == 16
    assert node.xhttp_path.startswith("/") and len(node.xhttp_path) > 8
    assert keys.public_key_from_private(node.reality.private_key) == node.reality.public_key


@pytest.mark.parametrize("name", ["", "Upper", "has space", "-lead", "x" * 33])
def test_bad_names_rejected(name):
    with pytest.raises(st.StateError):
        st.State().add_user(name)


def test_duplicates_rejected():
    s = st.State()
    s.add_user("me")
    with pytest.raises(st.StateError):
        s.add_user("me")
    s.add_node("n1", "1.2.3.4", sni="a.example")
    with pytest.raises(st.StateError):
        s.add_node("n1", "1.2.3.5", sni="a.example")


def test_rotate_keys_changes_identity():
    s = st.State()
    node = s.add_node("n1", "1.2.3.4", sni="a.example")
    before = (node.reality.private_key, node.reality.short_ids)
    s.rotate_node_keys("n1")
    assert (node.reality.private_key, node.reality.short_ids) != before


def test_save_load_roundtrip_is_private(tmp_path):
    path = tmp_path / "state" / "bibvpn.yml"
    s = st.State()
    s.add_node("n1", "1.2.3.4", sni="a.example")
    s.add_user("me", note="phone")
    st.save(s, path)
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert st.load(path) == s


def test_load_missing_file(tmp_path):
    with pytest.raises(st.StateError, match="bibvpn init"):
        st.load(tmp_path / "nope.yml")
