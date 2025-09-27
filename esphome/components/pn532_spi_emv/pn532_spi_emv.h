#pragma once

#include "esphome/components/nfc/nfc_tag.h"
#include "esphome/components/pn532_spi/pn532_spi.h"

#include <memory>
#include <string>
#include <vector>

namespace esphome {
namespace pn532_spi_emv {

class PN532SpiEmv : public pn532_spi::PN532Spi {
 public:
  void loop() override;
  void set_salt(const std::string &salt) { this->salt_ = salt; }

 protected:
  std::unique_ptr<nfc::NfcTag> read_emv_tag_(const std::vector<uint8_t> &uid);
  bool send_apdu_(const std::vector<uint8_t> &apdu, std::vector<uint8_t> &response);
  bool parse_tlv_find_(const std::vector<uint8_t> &buffer, uint16_t needle, std::vector<uint8_t> &value);
  bool parse_track2_digits_(const std::vector<uint8_t> &track2, std::vector<uint8_t> &digits);
  bool parse_track1_digits_(const std::vector<uint8_t> &track1, std::vector<uint8_t> &digits);
  bool parse_tag5a_digits_(const std::vector<uint8_t> &bcd, std::vector<uint8_t> &digits);
  bool build_hashed_pan_ndef_(const std::vector<uint8_t> &digits, std::vector<uint8_t> &ndef_out);
  std::vector<uint8_t> construct_pdol_payload_(const std::vector<uint8_t> &pdol);
  bool read_record_pan_(uint8_t record, uint8_t sfi, std::vector<uint8_t> &digits);

  std::string salt_ = "esphome_pn532";
};

}  // namespace pn532_spi_emv
}  // namespace esphome
