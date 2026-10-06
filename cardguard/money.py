from decimal import Decimal

_exponent =  {
    "JPY" : 0, "KRW": 0, "VND": 0, "XOF": 0, "XAF": 0, "UGX": 0, "RWF": 0,
      "KWD": 3, "BHD": 3, "OMR": 3, "JOD": 3, "TND": 3, "NGN": 2, "CLP": 0, "PYG": 0, "MGA": 1, "BIF": 0, "GNF": 0, "MWK": 2,
      "USD": 2, "EUR": 2, "GBP": 2,
    
}

def money(amount_minor: int, currency: str) -> str:
    """
    Render minor unit for a human: 10000 USD -> '$100.00 USD' .
    Customers must never see  minor raw unit('10000 USD' reads as ten thousand dollars)
    because it is confusing and error-prone. Always use this function to render money amounts for humans.   
    """
    exp = _exponent.get(currency, 2)
    value = Decimal(amount_minor) .scaleb(-exp)
    return f"{value:,.{exp}f} {currency}"

