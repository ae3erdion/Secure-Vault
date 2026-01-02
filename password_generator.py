import secrets
import string

DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

def generate_password(
    length=16,
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_symbols=True
):
    if length < 8:
        raise ValueError("Password length too short")

    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += DEFAULT_SYMBOLS

    if not charset:
        raise ValueError("No character sets selected")

    return "".join(secrets.choice(charset) for _ in range(length))
