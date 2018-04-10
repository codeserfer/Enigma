from Crypto.Cipher import AES

from django.db import models
from django.utils.translation import ugettext as _
from django.conf import settings

from core.models import User
from crypto.utils import get_hex_uuid


DB_CODE_LENGTH = settings.DB_CODE_LENGTH
IDENTIFY_KEY_LENGTH = settings.IDENTIFY_KEY_LENGTH
URL_KEY_LENGTH = settings.URL_KEY_LENGTH
ENCRYPTION_KEY_LENGTH = 32


class EncryptedData(models.Model):
    # Translators: Идентификационный ключ
    identify_key = models.UUIDField(verbose_name=_('identify key'), null=False, blank=False)
    # Translators: Данные
    data = models.BinaryField(verbose_name=_('data'))
    # Translators: Дата и время добавления
    add_dt = models.DateTimeField(verbose_name=_('date and time of adding'), auto_now=True)
    # Translators: Дата и время удаления
    delete_dt = models.DateTimeField(verbose_name=_('date and time of deleting'), null=True)
    # Translators: Количество открытий всего
    total_times = models.IntegerField(verbose_name=_('times of opening total'), null=True)
    # Translators: Количество открытий
    actual_times = models.IntegerField(verbose_name=_('times of opening'), null=True)
    # Translators: Пользователь
    user = models.ForeignKey(
        User, verbose_name=_('user'), related_name='encrypted_data', null=True, on_delete=models.SET_NULL
    )
    # Translators: Инициализационный вектор
    init_vector = models.BinaryField(verbose_name=_('initial vector'), null=True, blank=True)
    # Translation: Ключ из базы данных
    db_key = models.TextField(verbose_name=_('code from database'))

    @staticmethod
    def generate_encryption_data():
        """
        Generates keys used for encryption and building url
        """
        code_key = settings.CODE_KEY
        db_key = get_hex_uuid()
        identify_key = get_hex_uuid()
        url_key = get_hex_uuid()

        return code_key, db_key, identify_key, url_key

    @staticmethod
    def cut_encryption_data(code_key, db_key, identify_key, url_key):
        """
        Cut encryption data according lengths from settings
        """
        code_key = code_key
        db_key = db_key[:DB_CODE_LENGTH]
        identify_key = identify_key[:IDENTIFY_KEY_LENGTH]
        url_key = url_key[:URL_KEY_LENGTH]

        return code_key, db_key, identify_key, url_key

    @staticmethod
    def get_encryption_key(code_key, db_key, url_key):
        """
        :param code_key: encryption key from program code
        :param db_key: encryption key from db
        :param url_key: key stored only in url, only user owns it
        :return: key using for encryption user data, it must have 32 bytes
        """
        encryption_key = '{code_key}{db_key}{url_key}'.format(
            code_key=code_key,
            db_key=db_key,
            url_key=url_key,
        ).encode('utf8')

        if len(encryption_key) != ENCRYPTION_KEY_LENGTH:
            raise ValueError

        return encryption_key

    @staticmethod
    def build_url(url_key, identify_key):
        return '{}{}'.format(url_key, identify_key)

    @classmethod
    def parse_url(cls, url):
        identify_key = url[URL_KEY_LENGTH:]
        item = cls.objects.get(identify_key=identify_key)
        return item, url[:URL_KEY_LENGTH]

    @classmethod
    def encrypt(cls, text, delete_dt=None, total_times=None):
        code_key, db_key, identify_key, url_key = cls.generate_encryption_data()
        key_code_cut, db_code_cut, identify_key_cut, url_key_cut = cls.cut_encryption_data(
            code_key, db_key, identify_key, url_key
        )
        encryption_key = cls.get_encryption_key(key_code_cut, db_code_cut, url_key_cut)
        cipher = AES.new(encryption_key, AES.MODE_CFB)
        data = cipher.encrypt(text.encode('utf8'))

        item = cls(
            data=data,
            delete_dt=delete_dt,
            total_times=total_times,
            init_vector=cipher.iv,
            identify_key=identify_key,
            db_key=db_key
        )
        item.save()

        url = cls.build_url(url_key_cut, identify_key)

        return url, item

    @classmethod
    def decrypt(cls, url):
        item, url_key = cls.parse_url(url)
        encryption_key = cls.get_encryption_key(settings.CODE_KEY, item.db_key[:DB_CODE_LENGTH], url_key)
        cipher = AES.new(encryption_key, AES.MODE_CFB, iv=item.init_vector)
        return cipher.decrypt(item.data).decode('utf-8')
