"""Binary sensor: device fault/error."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import Asp100Entity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    if "error" in (coordinator.data or {}):
        async_add_entities([Asp100ErrorSensor(coordinator)])


class Asp100ErrorSensor(Asp100Entity, BinarySensorEntity):
    _attr_translation_key = "error"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    @property
    def unique_id(self) -> str:
        return f"{self.coordinator.device.mac}_error"

    @property
    def is_on(self) -> bool | None:
        err = self._state.get("error")
        return None if err is None else err != 0

    @property
    def extra_state_attributes(self) -> dict:
        return {"error_code": self._state.get("error")}
