"""Constants for the Ballu ASP-100 (Syncleo local) integration."""

DOMAIN = "asp100"

# config entry keys
CONF_MAC = "mac"
CONF_TOKEN = "token"
CONF_HOST = "host"  # optional static IP override

DEFAULT_PORT = 41122
DEFAULT_SCAN_INTERVAL = 30  # seconds

# ASP-100 (device catalog type 69): speed slider min=1 max=7, active in program 1 (Manual).
SPEED_MIN = 1
SPEED_MAX = 7

# operating programs selected via CmdMode (0x01). 0 = Off; 1-5 are "on" programs.
# Turbo is program 4 (firmware runs it ~15 min). Exposed as climate preset_modes.
PROGRAM_OFF = 0
PROGRAM_MANUAL = 1
PROGRAMS = {1: "manual", 2: "auto", 3: "night", 4: "turbo", 5: "fan"}
PRESET_TO_PROGRAM = {name: num for num, name in PROGRAMS.items()}
PRESET_MODES = list(PROGRAMS.values())

# manufacturer/model for the HA device registry
MANUFACTURER = "Ballu / Rusklimat (Syncleo)"
MODEL = "ASP-100 breezer"
