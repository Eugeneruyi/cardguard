from decimal import Decimal

# ISO 4217 minor-unit exponents that are not 2.
_EXPONENT = {
    "JPY": 0, "KRW": 0, "VND": 0, "XOF": 0, "XAF": 0, "UGX": 0, "RWF": 0,
    "KWD": 3, "BHD": 3, "OMR": 3, "JOD": 3, "TND": 3,
}


def money(amount_minor: int, currency: str) -> str:
    """Render minor units for a human: 10000 USD -> '100.00 USD'.
    Customers must never see raw minor units ('10000 USD' reads as ten thousand)."""
    exp = _EXPONENT.get(currency, 2)
    value = Decimal(amount_minor).scaleb(-exp)
    return f"{value:,.{exp}f} {currency}"
