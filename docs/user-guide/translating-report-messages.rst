Translating the report messages
===============================
This section describes how to translate the Artemis report messages described in
:ref:`generating-reports`.

The translations reside in:

- ``artemis/reporting/modules/nuclei/translations/nuclei_messages/{language}.py`` - this file
  contains Nuclei message translations,
- ``.po`` files in respective modules in ``artemis/reporting/modules/`` - these files contain
  translations of all other messages.

  If the original messages changed, update the ``.po`` files by running:

  ``./scripts/update_translation_files``

  and then put the translations in the respective ``.po`` files. The compilation will happen
  automatically when building the report messages.


Adding a new language
---------------------

If you want to support a new language:

- add it in ``./scripts/update_translation_files``,
- add it in ``artemis/reporting/base/language.py``,
- if you want SPF/DMARC verification messages to be supported, add support in https://github.com/CERT-Polska/mailgoose
  (https://mailgoose.readthedocs.io/en/latest/user-guide/translation.html).

The following file need to be created manually when adding support for a new
language: ``artemis/reporting/modules/nuclei/translations/nuclei_messages/{language}.py`` - this file
contains Nuclei message translations.

If you want to add or modify all other translation messages, first update the translation files by using:

``./scripts/update_translation_files``

and then put the translations in the respective ``.po`` files. The compilation will happen
automatically when building the report messages.
