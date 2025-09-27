#pragma once

#include "esphome/core/component.h"
#include "esphome/components/nfc/automation.h"
#include "esphome/components/nfc/nfc_tag.h"
#include "esphome/components/pn532/pn532.h"
#include "esphome/core/hal.h"

#include <memory>
#include <string>
#include <vector>

namespace esphome {
namespace pn532_spi_emv {

class PN532SpiEmv : public Component {
 public:
  void set_parent(pn532::PN532 *parent);
  void set_salt(const std::string &salt) { this->salt_ = salt; }
  void set_busy_pin(GPIOPin *pin);

 protected:
  void handle_tag(const std::unique_ptr<nfc::NfcTag> &tag);
  std::unique_ptr<nfc::NfcTag> read_emv_tag_(const std::vector<uint8_t> &uid);
  bool send_apdu_(const std::vector<uint8_t> &apdu, std::vector<uint8_t> &response);
  bool parse_tlv_find_(const std::vector<uint8_t> &buffer, uint16_t needle, std::vector<uint8_t> &value);
  bool parse_track2_digits_(const std::vector<uint8_t> &track2, std::vector<uint8_t> &digits);
  bool parse_track1_digits_(const std::vector<uint8_t> &track1, std::vector<uint8_t> &digits);
  bool parse_tag5a_digits_(const std::vector<uint8_t> &bcd, std::vector<uint8_t> &digits);
  bool build_hashed_pan_ndef_(const std::vector<uint8_t> &digits, std::vector<uint8_t> &ndef_out);
  std::vector<uint8_t> construct_pdol_payload_(const std::vector<uint8_t> &pdol);
  bool read_record_pan_(uint8_t record, uint8_t sfi, std::vector<uint8_t> &digits);

  pn532::PN532 *parent_{nullptr};
  std::unique_ptr<nfc::NfcOnTagTrigger> internal_trigger_;
  GPIOPin *busy_pin_{nullptr};
  std::string salt_{"esphome_pn532"};
};

}  // namespace pn532_spi_emv
}  // namespace esphome
