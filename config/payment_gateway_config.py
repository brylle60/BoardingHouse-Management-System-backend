
import os


class PayPalConfig:
    client_id:  str = os.getenv("PAYPAL_CLIENT_ID",  "")
    secret_key: str = os.getenv("PAYPAL_SECRET_KEY", "")
    mode:       str = os.getenv("PAYPAL_MODE",       "sandbox")   # "sandbox" | "live"
    currency:   str = os.getenv("PAYPAL_CURRENCY",   "PHP")

    # Where PayPal redirects after tenant approves / cancels
    return_url: str = os.getenv("PAYPAL_RETURN_URL", "")
    cancel_url: str = os.getenv("PAYPAL_CANCEL_URL", "")

    @property
    def base_url(self) -> str:
        return (
            "https://api-m.sandbox.paypal.com"
            if self.mode == "sandbox"
            else "https://api-m.paypal.com"
        )


# Singleton — import this everywhere
paypal_cfg = PayPalConfig()
