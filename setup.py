from setuptools import setup, find_packages

setup(
    name="go-auth",
    version="0.1.4a",
    url='https://github.com/praekelt/go-auth',
    license='BSD',
    description="Authentication services and utilities for Vumi Go APIs.",
    long_description=open('README.rst', 'r').read(),
    author='Praekelt Foundation',
    author_email='dev@praekeltfoundation.org',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cyclone',
        'oauthlib',
        'go_api',
        'PyYAML',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
