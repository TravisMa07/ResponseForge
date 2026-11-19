import pytest

from tests.rf07b.helpers import make_material


@pytest.fixture(scope="session")
def material(tmp_path_factory):
    return make_material(tmp_path_factory.mktemp("rf07b-ephemeral-material").resolve() / "private")
