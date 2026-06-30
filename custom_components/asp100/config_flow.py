"""Config flow for ASP-100: ask for MAC + token (+ optional static IP)."""

from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import config_validation as cv

from .const import CONF_HOST, CONF_MAC, CONF_TOKEN, DOMAIN
from .device import Asp100Device, AuthError, DeviceUnavailable

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_MAC): str,
        vol.Required(CONF_TOKEN): str,
        vol.Optional(CONF_HOST): str,
    }
)


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


class Asp100ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ASP-100."""

    VERSION = 1

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            mac = _normalize_mac(user_input[CONF_MAC])
            token = user_input[CONF_TOKEN].strip()
            host = user_input.get(CONF_HOST)

            await self.async_set_unique_id(mac)
            self._abort_if_unique_id_configured()

            try:
                bytes.fromhex(token)
            except ValueError:
                errors["base"] = "invalid_token"

            if not errors:
                device = Asp100Device(mac=mac, token=token, host=host)
                try:
                    # validate by authenticating + a quick state read
                    await self.hass.async_add_executor_job(device.read_state, 2.0)
                except AuthError:
                    errors["base"] = "auth_failed"
                except DeviceUnavailable:
                    errors["base"] = "cannot_connect"
                except Exception:  # noqa: BLE001
                    errors["base"] = "unknown"

            if not errors:
                return self.async_create_entry(
                    title=f"ASP-100 {mac}",
                    data={CONF_MAC: mac, CONF_TOKEN: token, CONF_HOST: host},
                )

        return self.async_show_form(
            step_id="user", data_schema=DATA_SCHEMA, errors=errors
        )
