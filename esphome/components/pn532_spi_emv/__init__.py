import esphome.codegen as cg
from esphome.components import pn532
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome import pins

CONF_PN532_ID = "pn532_id"
CONF_SALT = "salt"
CONF_BUSY_PIN = "busy_pin"

CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["pn532"]

pn532_spi_emv_ns = cg.esphome_ns.namespace("pn532_spi_emv")
PN532SpiEmv = pn532_spi_emv_ns.class_("PN532SpiEmv", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(PN532SpiEmv),
        cv.Required(CONF_PN532_ID): cv.use_id(pn532.PN532),
        cv.Optional(CONF_SALT, default="esphome_pn532"): cv.string,
        cv.Optional(CONF_BUSY_PIN): pins.gpio_output_pin_schema,
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    parent = await cg.get_variable(config[CONF_PN532_ID])
    cg.add(var.set_parent(parent))
    cg.add(var.set_salt(config[CONF_SALT]))

    if CONF_BUSY_PIN in config:
        pin = await cg.gpio_pin_expression(config[CONF_BUSY_PIN])
        cg.add(var.set_busy_pin(pin))
