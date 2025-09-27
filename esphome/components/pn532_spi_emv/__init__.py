import esphome.codegen as cg
from esphome.components import pn532, pn532_spi, spi
import esphome.config_validation as cv
from esphome.const import CONF_ID

CONF_SALT = "salt"

AUTO_LOAD = ["pn532_spi"]
CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["spi"]
MULTI_CONF = True

pn532_spi_emv_ns = cg.esphome_ns.namespace("pn532_spi_emv")
PN532SpiEmv = pn532_spi_emv_ns.class_("PN532SpiEmv", pn532_spi.PN532Spi)

CONFIG_SCHEMA = pn532.PN532_SCHEMA.extend(
    {
        cv.GenerateID(): cv.declare_id(PN532SpiEmv),
        cv.Optional(CONF_SALT, default="esphome_pn532"): cv.string,
    }
).extend(spi.spi_device_schema(cs_pin_required=True))


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await pn532.setup_pn532(var, config)
    await spi.register_spi_device(var, config)
    cg.add(var.set_salt(config[CONF_SALT]))
