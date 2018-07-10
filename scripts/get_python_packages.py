"""This script prints names of all packages in PyPI to stdout."""

from bs4 import BeautifulSoup
import requests


def get_package_names():
    """Get names of all packages in PyPI."""
    pypi_packages_url = 'https://pypi.python.org/simple/'
    response = requests.get(pypi_packages_url)
    if response.status_code != 200:
        raise Exception('Error fetching URL: {url}'.format(url=pypi_packages_url))

    soup = BeautifulSoup(response.content, 'html.parser')
    for link in soup.find_all('a'):
        path = link.get('href')
        package = path.split('/')[2]
        yield package


if __name__ == '__main__':
    for package in get_package_names():
        print('python,' + package)
