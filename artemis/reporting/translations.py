import re
from typing import List, Tuple

PLACEHOLDER = "__PLACEHOLDER__"


def translate_using_dictionary(message: str, dictionary: List[Tuple[str, str]]) -> str:
    """Translates message according to a dictionary.

    For example, for the following dictionary:

    [
        (f"Input message one {PLACEHOLDER}.", f"Output message one {PLACEHOLDER}."),
        (f"Input message two {PLACEHOLDER}.", f"Output message two {PLACEHOLDER}."),
    ]

    message "Input message one 1234." will get translated to "Output message one 1234.".

    *note* the "from" and "to" messages must have the same number of placeholders -
    and will have the same order of placeholders.
    """
    for m_from, m_to in dictionary:
        pattern = "^" + re.escape(m_from).replace(PLACEHOLDER, "(.*)") + "$"
        regexp_match = re.match(pattern, message)

        # a dictionary rule matched the message
        if regexp_match:
            result = m_to
            for matched in regexp_match.groups():
                # replace first occurence of placeholder with the matched needle
                result = result.replace(PLACEHOLDER, matched, 1)
            return result

    raise NotImplementedError(f"Unable to translate {message}")
