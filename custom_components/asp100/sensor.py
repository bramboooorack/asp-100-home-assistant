"""Sensor entities for the ASP-100 (the readings climate can't hold)."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
    CONCENTRATION_PARTS_PER_MILLION,
    PERCENTAGE,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import Asp100Entity


@dataclass(frozen=True, kw_only=True)
class Asp100SensorDescription(SensorEntityDescription):
    value_key: str = ""


SENSORS: tuple[Asp100SensorDescription, ...] = (
    Asp100SensorDescription(
        key="current_temperature",
        value_key="current_temperature",
        translation_key="current_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Asp100SensorDescription(
        key="current_humidity",
        value_key="current_humidity",
        translation_key="current_humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Asp100SensorDescription(
        key="co2",
        value_key="co2",
        translation_key="co2",
        device_class=SensorDeviceClass.CO2,
        native_unit_of_measurement=CONCENTRATION_PARTS_PER_MILLION,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Asp100SensorDescription(
        key="pm25",
        value_key="pm25",
        translation_key="pm25",
        device_class=SensorDeviceClass.PM25,
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Asp100SensorDescription(
        key="filter",
        value_key="filter",
        translation_key="filter",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:air-filter",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    data = coordinator.data or {}
    # only create sensors the device actually reports
    async_add_entities(
        Asp100Sensor(coordinator, desc)
        for desc in SENSORS
        if desc.value_key in data
    )


class Asp100Sensor(Asp100Entity, SensorEntity):
    entity_description: Asp100SensorDescription

    def __init__(self, coordinator, description: Asp100SensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.device.mac}_{description.key}"

    @property
    def native_value(self):
        return self._state.get(self.entity_description.value_key)
