# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os, sys, subprocess
sys.path.insert(0, os.path.abspath('.'))

if os.environ.get('READTHEDOCS', None) == 'True':
  subprocess.call('doxygen')


# -- Project information -----------------------------------------------------

project = 'IOTA C Client'
copyright = '2021, IOTA Stiftung'
author = 'Sam Chen'

master_doc = "index"
highlight_language = 'c'
primary_domain = 'c'
language = "en"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['myst_parser', 'breathe']

# Auto-generated header anchors
myst_heading_anchors = 2

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_book_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

## myst-parser settings

## breathe settings

breathe_default_project = 'iota.c'
breathe_domain_by_extension = {'h' : 'c'}
breathe_projects = { 'iota.c': './doxygen_build/xml/' }