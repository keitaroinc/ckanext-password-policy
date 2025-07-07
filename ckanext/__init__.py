# encoding: utf-8

# this is a namespace package




from future import standard_library
standard_library.install_aliases()
try:
    import pkg_resources
    pkg_resources.declare_namespace(__name__)
except ImportError:
    import pkgutil
    __path__ = pkgutil.extend_path(__path__, __name__)
