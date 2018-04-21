from factory import fuzzy

from django.test import TestCase, override_settings
from django.utils import timezone

from application import settings
from crypto.models import EncryptedData, CanNotEncodeException
from crypto.tests.factories import TEXT_LENGTH, EncryptedDataWithDateFactory


class TestEncryptionAndDecryption(TestCase):
    def test_encrypt_and_decrypt(self):
        text = fuzzy.FuzzyText(length=TEXT_LENGTH).fuzz()
        url, _ = EncryptedData.encrypt(text=text)

        decrypted_text = EncryptedData.decrypt(url)

        self.assertEqual(text, decrypted_text)


class TestDeleteDT(TestCase):
    def test_delete_dt_in_past(self):
        with self.assertRaises(Exception) as cm:
            EncryptedDataWithDateFactory(delete_dt=timezone.now() - timezone.timedelta(weeks=1))
        exception = cm.exception

        self.assertIsInstance(exception, ValueError)

    def test_delete_dt_in_future(self):
        url, encrypted_data_object = EncryptedDataWithDateFactory()
        self.assertGreaterEqual(encrypted_data_object.delete_dt, timezone.now())


class BaseEncryptedDataTestCase(TestCase):
    TOTAL_TIMES = 5

    def setUp(self):
        self.url, self.encrypted_data_object = EncryptedDataWithDateFactory(total_times=self.TOTAL_TIMES)


class TestOpenTimes(BaseEncryptedDataTestCase):
    def test_one_open(self):
        EncryptedData.decrypt(self.url)

        actual_times_before = self.encrypted_data_object.actual_times
        self.encrypted_data_object.refresh_from_db()
        actual_times_after = self.encrypted_data_object.actual_times

        self.assertEqual(actual_times_before + 1, actual_times_after)

    def test_total_opens(self):
        for _ in range(0, self.TOTAL_TIMES):
            EncryptedData.decrypt(self.url)

        with self.assertRaises(Exception) as cm:
            self.encrypted_data_object.refresh_from_db()
        exception = cm.exception
        self.assertIsInstance(exception, EncryptedData.DoesNotExist)

        with self.assertRaises(Exception) as cm:
            EncryptedData.decrypt(self.url)
        exception = cm.exception
        self.assertIsInstance(exception, EncryptedData.DoesNotExist)


class TestDecryptionWithIncorrectKeys(BaseEncryptedDataTestCase):
    def test_with_incorrect_url_key(self):
        _, url_key = EncryptedData.parse_url(self.url)

        new_url = self.url.replace(url_key, '0'*len(url_key))

        with self.assertRaises(Exception) as cm:
            EncryptedData.decrypt(new_url)
        exception = cm.exception
        self.assertIsInstance(exception, CanNotEncodeException)

    @override_settings(CODE_KEY='0'*len(settings.CODE_KEY))
    def test_with_incorrect_code_key(self):
        with self.assertRaises(Exception) as cm:
            EncryptedData.decrypt(self.url)
        exception = cm.exception
        self.assertIsInstance(exception, CanNotEncodeException)

    def test_with_incorrect_db_key(self):
        self.encrypted_data_object.db_key = '0' * len(self.encrypted_data_object.db_key)
        self.encrypted_data_object.save()

        with self.assertRaises(Exception) as cm:
            EncryptedData.decrypt(self.url)
        exception = cm.exception
        self.assertIsInstance(exception, CanNotEncodeException)
