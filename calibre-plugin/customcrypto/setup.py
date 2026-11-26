import io
import os

from setuptools import setup

here = os.path.dirname(os.path.abspath(__file__))
with io.open(os.path.join(here, 'readme.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='customcrypto',
    version='0.0.1',
    description='PKCS#12 key and certificate extraction with PyCryptodome, stripped down from oscrypto and asn1crypto',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    packages=['customcrypto'],
    # 2.7.8 added hashlib.pbkdf2_hmac, 2.7.7 hmac.compare_digest
    python_requires='>=2.7.8, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
    install_requires=[
        "pycryptodome"
    ],
    options={'bdist_wheel': {'universal': True}},
)
