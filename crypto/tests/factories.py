import factory
from factory import fuzzy

from crypto.models import EncryptedData

TEXT_LENGTH = 100000


class SimpleEncryptedDataFactory(factory.DjangoModelFactory):
    """
    Create EncryptedData with text only
    """
    class Meta:
        model = EncryptedData

    text = fuzzy.FuzzyText(length=TEXT_LENGTH)
