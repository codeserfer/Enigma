from django.test import TestCase
from factory import fuzzy

from crypto.models import EncryptedData
from crypto.tests.factories import TEXT_LENGTH


class TestEncryptionAndDecryption(TestCase):
    def test_encrypt_and_decrypt(self):
        text = fuzzy.FuzzyText(length=TEXT_LENGTH).fuzz()
        url, _ = EncryptedData.encrypt(text=text)

        decrypted_text = EncryptedData.decrypt(url)

        self.assertEqual(text, decrypted_text)
