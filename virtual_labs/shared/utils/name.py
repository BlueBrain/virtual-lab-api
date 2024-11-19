def extract_name_parts(name: str) -> tuple[str, str]:
    """
    Extracts the first name and last name from a given full name.

    Args:
        name (str): The full name of the person.

    Returns:
        tuple[str, str]: A tuple containing the first name and last name.
                         If the name has only one word, the last name will be an empty string.
    """
    name_parts = name.strip().split(maxsplit=1)

    if len(name_parts) == 1:
        firstname = name_parts[0]
        lastname = ""
    else:
        firstname, lastname = name_parts[0], name_parts[1]

    return firstname, lastname
