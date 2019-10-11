from setuptools import setup, find_packages

setup(
    name='conmets',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    #version='0.0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'conmets = conmets.main:main',
        ],
    },
    install_requires=[
        'certifi',
        'numpy',
        'matplotlib',
        'pandas',
        'PyYAML',
    ],
    extras_require={
        'test': [
            'pytest',
        ],
    }
)
