"""Sphinx configuration for GNAT documentation."""
import os, sys
sys.path.insert(0, os.path.abspath("../.."))

project   = "GNAT"
author    = "GNAT Contributors"
copyright = "2025, GNAT Contributors"
release   = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx_copybutton",
]

napoleon_numpy_docstring       = True
napoleon_google_docstring      = False
napoleon_include_init_with_doc = True
napoleon_use_param             = True
napoleon_use_rtype             = True

autodoc_default_options = {
    "members": True, "undoc-members": False,
    "show-inheritance": True, "special-members": "__init__",
}
autosummary_generate = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "urllib3": ("https://urllib3.readthedocs.io/en/stable/", None),
}

html_theme       = "furo"
html_static_path = ["_static"]
html_title       = "GNAT"
html_theme_options = {
    "navigation_with_keys": True,
    "light_css_variables": {"color-brand-primary": "#1a73e8", "color-brand-content": "#1a73e8"},
    "dark_css_variables":  {"color-brand-primary": "#4ea8de", "color-brand-content": "#4ea8de"},
}
exclude_patterns   = ["_build", "Thumbs.db", ".DS_Store"]
templates_path     = ["_templates"]
todo_include_todos = True
