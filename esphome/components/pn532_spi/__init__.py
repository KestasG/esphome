import esphome.codegen as cg
from esphome.components import pn532, spi
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome import pins

AUTO_LOAD = ["pn532"]
CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["spi"]
MULTI_CONF = True

# New config key
CONF_SALT = "salt"
CONF_BUSY_PIN = "busy_pin" 

pn532_spi_ns = cg.esphome_ns.namespace("pn532_spi")
PN532Spi = pn532_spi_ns.class_("PN532Spi", pn532.PN532, spi.SPIDevice)

CONFIG_SCHEMA = cv.All(
    pn532.PN532_SCHEMA.extend(
        {
            cv.GenerateID(): cv.declare_id(PN532Spi),
            cv.Optional(CONF_SALT): cv.string,
            cv.Optional(CONF_BUSY_PIN): pins.gpio_output_pin_schema 
        }
    ).extend(spi.spi_device_schema(cs_pin_required=True))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await pn532.setup_pn532(var, config)
    await spi.register_spi_device(var, config)

    # Wire the YAML 'salt:' into the C++ object (expects PN532::set_salt(const std::string&))
    if CONF_SALT in config:
        cg.add(var.set_salt(config[CONF_SALT]))
    
    if CONF_BUSY_PIN in config:
        pin = await cg.gpio_pin_expression(config[CONF_BUSY_PIN])
        cg.add(var.set_busy_pin(pin))
