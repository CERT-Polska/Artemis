Translating the report messages
===============================
This section describes how to translate the Artemis report messages described in
:ref:`generating-e-mails`.

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

If you want to support a new language, add it in ``./scripts/update_translation_files`` and
``artemis/reporting/base/language.py``.

The following message files need to be created manually when adding support for a new
language:

- ``artemis/reporting/modules/nuclei/translations/nuclei_messages/{language}.py`` - this file
  contains Nuclei message translations,
- ``artemis/reporting/modules/mail_dns_scanner/translations/{language}/additional.po`` - this file
  contains translations for the e-mail configuration (SPF, DMARC) check library messages (you may
  copy and modify ``artemis/reporting/modules/mail_dns_scanner/translations/pl_PL/additional.po``).

If you want to add or modify all other translation messages, first update the translation files by using:

``./scripts/update_translation_files``

and then put the translations in the respective ``.po`` files. The compilation will happen
automatically when building the report messages.
