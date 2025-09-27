import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import pn532, spi, pn532_spi   # <-- import base
from esphome.const import CONF_ID
from esphome import pins

AUTO_LOAD = ["pn532","pn532_spi"]   # <-- pull in the base component
CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["spi"]               # only depends on SPI bus
MULTI_CONF = True

pn532_spi_emv_ns = cg.esphome_ns.namespace("pn532_spi_emv")
PN532SpiEMV = pn532_spi_emv_ns.class_("PN532SpiEMV", pn532_spi.PN532Spi)

CONFIG_SCHEMA = cv.All(
    pn532.PN532_SCHEMA.extend({
        cv.GenerateID(): cv.declare_id(PN532SpiEMV),
        cv.Optional("salt"): cv.string,
        cv.Optional("busy_pin"): pins.gpio_output_pin_schema,
    }).extend(spi.spi_device_schema(cs_pin_required=True))
)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await pn532.setup_pn532(var, config)
    await spi.register_spi_device(var, config)
    if "salt" in config:
        cg.add(var.set_salt(config["salt"]))
    if "busy_pin" in config:
        pin = await cg.gpio_pin_expression(config["busy_pin"])
        cg.add(var.set_busy_pin(pin))
