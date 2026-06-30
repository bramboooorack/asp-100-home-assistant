"""Climate entity for the ASP-100 breezer (heat + fan speeds)."""

from __future__ import annotations

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DOMAIN,
    PRESET_MODES,
    PRESET_TO_PROGRAM,
    PROGRAM_MANUAL,
    PROGRAM_OFF,
    PROGRAMS,
    SPEED_MAX,
    SPEED_MIN,
)
from .entity import Asp100Entity

# 7 manual speed levels (catalog: speed slider min=1 max=7, active in program 1).
FAN_MODES = [str(s) for s in range(SPEED_MIN, SPEED_MAX + 1)]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([Asp100Climate(coordinator)])


class Asp100Climate(Asp100Entity, ClimateEntity):
    """Breezer as a climate device: target temp + fan speed + on/off."""

    _attr_name = None  # primary entity uses the device name
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = 1.0
    # from the device catalog (type 69): temperature min=5 max=25 default=18
    _attr_min_temp = 5
    _attr_max_temp = 25
    _attr_fan_modes = FAN_MODES
    _attr_preset_modes = PRESET_MODES  # manual / auto / night / turbo / fan
    # TODO: distinguish FAN_ONLY (heater off) from HEAT once we know the heater-state opcode.
    _attr_hvac_modes = [HVACMode.OFF, HVACMode.HEAT]
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.PRESET_MODE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
    )
    _enable_turn_on_off_backwards_compatibility = False

    @property
    def unique_id(self) -> str:
        return f"{self.coordinator.device.mac}_climate"

    @property
    def current_temperature(self) -> float | None:
        return self._state.get("current_temperature")

    @property
    def target_temperature(self) -> float | None:
        return self._state.get("target_temperature")

    @property
    def hvac_mode(self) -> HVACMode:
        # program/mode 0 = Off (device catalog). speed 0 also implies off.
        mode = self._state.get("mode")
        if mode == PROGRAM_OFF or not self._state.get("speed"):
            return HVACMode.OFF
        return HVACMode.HEAT

    @property
    def fan_mode(self) -> str | None:
        # only the 7 manual speeds are user-selectable; turbo/night run speed 8
        speed = self._state.get("speed")
        return str(speed) if speed and SPEED_MIN <= speed <= SPEED_MAX else None

    @property
    def preset_mode(self) -> str | None:
        return PROGRAMS.get(self._state.get("mode"))

    async def async_set_temperature(self, **kwargs) -> None:
        temp = kwargs.get(ATTR_TEMPERATURE)
        if temp is not None:
            await self.coordinator.async_send(
                self.coordinator.device.set_target_temperature, float(temp)
            )

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        await self.coordinator.async_send(
            self.coordinator.device.set_speed, int(fan_mode)
        )

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        # on/off = program (CmdMode 0x01): 0 = Off, 1 = manual (verified on hardware)
        program = PROGRAM_OFF if hvac_mode == HVACMode.OFF else PROGRAM_MANUAL
        await self.coordinator.async_send(self.coordinator.device.set_mode, program)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        # presets are the operating programs; turbo = program 4 (CmdMode=4)
        program = PRESET_TO_PROGRAM[preset_mode]
        await self.coordinator.async_send(self.coordinator.device.set_mode, program)

    async def async_turn_on(self) -> None:
        await self.async_set_hvac_mode(HVACMode.HEAT)

    async def async_turn_off(self) -> None:
        await self.async_set_hvac_mode(HVACMode.OFF)
