
from setuptools import setup, find_packages

from homedns.globalvars import version


with open('README.rst') as f:
    long_description = f.read()

requirements = []
with open('requirements.txt') as f:
    for line in f.readlines():
        line.strip()
        if line.startswith('#'):
            continue
        requirements.append(line)


setup(
    name='HomeDNS',
    version=version,
    author_email='liuyug@gmail.com',
    url='https://github.com/liuyug/homedns.git',
    license='GPLv3',
    description='This is a tiny DNS server for family used.',
    long_description=long_description,
    keywords='dns tiny home domain cname srv',
    python_requires='>=3',
    platforms=['noarch'],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'homedns = homedns.hdns:run',
        ],
    },
    install_requires=requirements,
    zip_safe=False,
)
