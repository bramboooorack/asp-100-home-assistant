"""DataUpdateCoordinator that polls the breezer state."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .device import Asp100Device, AuthError, DeviceUnavailable

_LOGGER = logging.getLogger(__name__)


class Asp100Coordinator(DataUpdateCoordinator[dict]):
    """Polls device state and caches it for all entities."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, device: Asp100Device) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {device.mac}",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )
        self.entry = entry
        self.device = device

    async def _async_update_data(self) -> dict:
        try:
            return await self.hass.async_add_executor_job(self.device.read_state)
        except AuthError as err:
            # token invalid -> trigger reauth in the UI
            raise UpdateFailed(f"authentication failed: {err}") from err
        except DeviceUnavailable as err:
            raise UpdateFailed(str(err)) from err

    async def async_send(self, func, *args) -> None:
        """Run a blocking write, then refresh state."""
        await self.hass.async_add_executor_job(func, *args)
        await self.async_request_refresh()
