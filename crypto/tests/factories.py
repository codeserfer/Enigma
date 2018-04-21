import factory
from factory import fuzzy

from django.utils import timezone

from crypto.models import EncryptedData

TEXT_LENGTH = 100000


class SimpleEncryptedDataFactory(factory.DjangoModelFactory):
    """
    Create EncryptedData with text only
    """
    class Meta:
        model = EncryptedData

    text = fuzzy.FuzzyText(length=TEXT_LENGTH)


class EncryptedDataWithDateFactory(SimpleEncryptedDataFactory):
    delete_dt = fuzzy.FuzzyDateTime(
        start_dt=timezone.now() + timezone.timedelta(days=1),
        end_dt=timezone.now() + timezone.timedelta(weeks=10)
    )
