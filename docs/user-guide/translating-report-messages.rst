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

- add it in ``artemis/reporting/languages.txt``,
- if you want SPF/DMARC verification messages to be supported, add support in https://github.com/CERT-Polska/mailgoose
  (https://mailgoose.readthedocs.io/en/latest/user-guide/translation.html).

The following file need to be created manually when adding support for a new
language: ``artemis/reporting/modules/nuclei/translations/nuclei_messages/{language}.py`` - this file
contains Nuclei message translations.

If you want to add or modify all other translation messages, first update the translation files by using:

``./scripts/update_translation_files``

and then put the translations in the respective ``.po`` files. The compilation will happen
automatically when building the report messages.

**You don't have to translate everything - pull requests with partial translations are also welcome!**

After modifying the translations, restart Artemis **in developer mode** so that the Docker images will be built
locally and your changes will be included:

``./scripts/start_dev``

Handling Missing Translations
------------------------------

By default, Artemis will use the original (English) text when a missing translation is encountered during report export,
and will collect all missing translations in a file for easy filling.

If you want to ensure that all translations are complete before generating reports, you can use the ``--strict-translations`` 
flag when running the export command:

``artemis export --strict-translations``

In strict mode, the export will raise an exception on the first missing translation, which was the original behavior.

In the default lenient mode:

1. Missing translations will use the original (English) text instead of raising an exception
2. A file named ``missing_translations.po`` will be generated in the ``advanced`` directory of the export
3. This file contains all the missing translations in .po format, ready to be filled in

Once you've filled in the missing translations in the generated file, you can copy them to the appropriate 
translation files in the Artemis codebase.
