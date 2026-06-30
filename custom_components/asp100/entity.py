"""Shared base entity for ASP-100."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER, MODEL
from .coordinator import Asp100Coordinator


class Asp100Entity(CoordinatorEntity[Asp100Coordinator]):
    """Base entity tying all platforms to one HA device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: Asp100Coordinator) -> None:
        super().__init__(coordinator)
        mac = coordinator.device.mac
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)},
            connections={("mac", mac)},
            manufacturer=MANUFACTURER,
            model=MODEL,
            name=f"ASP-100 {mac}",
            sw_version=coordinator.device.firmware,
        )

    @property
    def _state(self) -> dict:
        return self.coordinator.data or {}
