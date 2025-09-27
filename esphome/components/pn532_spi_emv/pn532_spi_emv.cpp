#include "pn532_spi_emv.h"

#include "esphome/components/nfc/nfc.h"
#include "esphome/components/nfc/nfc_tag.h"
#include "esphome/core/helpers.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "esphome/core/time.h"

#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#include "mbedtls/sha256.h"

#include <cctype>
#include <cstdio>
#include <ctime>

namespace esphome {
namespace pn532_spi_emv {

static const char *const TAG = "pn532.spi_emv";
static const uint8_t EMV_SAK_DESFIRE = 0x20;  // Common for DESFire / EMV contactless cards.

struct TlvHeader {
  uint16_t tag;
  size_t length;
  size_t header_len;
};

static bool parse_tlv_header(const std::vector<uint8_t> &buffer, size_t offset, TlvHeader &out) {
  if (offset >= buffer.size())
    return false;

  size_t cursor = offset;
  uint16_t tag = buffer[cursor++];
  if ((tag & 0x1F) == 0x1F) {
    if (cursor >= buffer.size())
      return false;
    tag = static_cast<uint16_t>((tag << 8) | buffer[cursor++]);
  }
  if (cursor >= buffer.size())
    return false;

  uint8_t len_byte = buffer[cursor++];
  size_t length = 0;
  if ((len_byte & 0x80) != 0) {
    uint8_t count = static_cast<uint8_t>(len_byte & 0x7F);
    if (count == 0 || cursor + count > buffer.size())
      return false;
    while (count--) {
      length = (length << 8) | buffer[cursor++];
    }
  } else {
    length = len_byte;
  }

  out = {tag, length, cursor - offset};
  return true;
}

static bool is_template_tag(uint16_t tag) {
  switch (tag) {
    case 0x6F:
    case 0xA5:
    case 0x77:
    case 0x70:
    case 0x61:
    case 0xBF0C:
      return true;
    default:
      return false;
  }
}

static void make_ndef_text_message(const std::string &text, std::vector<uint8_t> &out) {
  const char *type = "T";
  const std::string lang = "en";
  const uint8_t status = static_cast<uint8_t>(lang.size() & 0x3F);
  const size_t payload_len = 1 + lang.size() + text.size();

  out.clear();
  out.reserve(3 + 1 + payload_len);
  out.push_back(0xD1);  // MB|ME|SR|TNF=Well-known
  out.push_back(0x01);  // type length
  out.push_back(static_cast<uint8_t>(payload_len));
  out.push_back(static_cast<uint8_t>(type[0]));
  out.push_back(status);
  out.insert(out.end(), lang.begin(), lang.end());
  out.insert(out.end(), text.begin(), text.end());
}

void PN532SpiEmv::loop() {
  if (!this->requested_read_)
    return;

  auto ready = this->read_ready_(false);
  if (ready == WOULDBLOCK)
    return;

  bool success = false;
  std::vector<uint8_t> response;

  if (ready == READY) {
    success = this->read_response(PN532_COMMAND_INLISTPASSIVETARGET, response);
  } else {
    this->send_ack_();
  }

  this->requested_read_ = false;

  if (!success) {
    if (!this->current_uid_.empty()) {
      auto tag = make_unique<nfc::NfcTag>(this->current_uid_);
      for (auto *trigger : this->triggers_ontagremoved_)
        trigger->process(tag);
    }
    this->current_uid_.clear();
    this->turn_off_rf_();
    return;
  }

  if (response.empty())
    return;

  uint8_t num_targets = response[0];
  if (num_targets != 1) {
    if (!this->current_uid_.empty()) {
      auto tag = make_unique<nfc::NfcTag>(this->current_uid_);
      for (auto *trigger : this->triggers_ontagremoved_)
        trigger->process(tag);
    }
    this->current_uid_.clear();
    this->turn_off_rf_();
    return;
  }

  if (response.size() < 6)
    return;

  uint8_t sel_res = response[4];
  uint8_t nfcid_length = response[5];
  if (response.size() < 6U + nfcid_length)
    return;

  std::vector<uint8_t> uid(response.begin() + 6, response.begin() + 6 + nfcid_length);

  bool report = true;
  for (auto *bin_sens : this->binary_sensors_) {
    if (bin_sens->process(uid))
      report = false;
  }

  if (uid.size() == this->current_uid_.size() && !uid.empty()) {
    bool same = true;
    for (size_t i = 0; i < uid.size(); ++i)
      same &= uid[i] == this->current_uid_[i];
    if (same)
      return;
  }

  this->current_uid_ = uid;

  if (this->next_task_ == READ) {
    std::unique_ptr<nfc::NfcTag> tag;

    if (sel_res == EMV_SAK_DESFIRE) {
      tag = this->read_emv_tag_(uid);
    }

    if (!tag) {
      tag = pn532::PN532::read_tag_(uid);
    }

    if (!tag) {
      auto uid_copy = uid;
      tag = make_unique<nfc::NfcTag>(uid_copy);
    }

    for (auto *trigger : this->triggers_ontag_)
      trigger->process(tag);

    if (report) {
      ESP_LOGD(TAG, "Found new tag '%s'", nfc::format_uid(uid).c_str());
      if (tag->has_ndef_message()) {
        const auto &message = tag->get_ndef_message();
        const auto &records = message->get_records();
        ESP_LOGD(TAG, "  NDEF formatted records:");
        for (const auto &record : records) {
          ESP_LOGD(TAG, "    %s - %s", record->get_type().c_str(), record->get_payload().c_str());
        }
      }
    }
  } else if (this->next_task_ == CLEAN) {
    ESP_LOGD(TAG, "  Tag cleaning");
    if (!pn532::PN532::clean_tag_(uid)) {
      ESP_LOGE(TAG, "  Tag was not fully cleaned successfully");
    }
    ESP_LOGD(TAG, "  Tag cleaned!");
  } else if (this->next_task_ == FORMAT) {
    ESP_LOGD(TAG, "  Tag formatting");
    if (!pn532::PN532::format_tag_(uid)) {
      ESP_LOGE(TAG, "Error formatting tag as NDEF");
    }
    ESP_LOGD(TAG, "  Tag formatted!");
  } else if (this->next_task_ == WRITE) {
    if (this->next_task_message_to_write_ != nullptr) {
      ESP_LOGD(TAG, "  Tag writing");
      ESP_LOGD(TAG, "  Tag formatting");
      if (!pn532::PN532::format_tag_(uid)) {
        ESP_LOGE(TAG, "  Tag could not be formatted for writing");
      } else {
        ESP_LOGD(TAG, "  Writing NDEF data");
        if (!pn532::PN532::write_tag_(uid, this->next_task_message_to_write_)) {
          ESP_LOGE(TAG, "  Failed to write message to tag");
        }
        ESP_LOGD(TAG, "  Finished writing NDEF data");
        delete this->next_task_message_to_write_;
        this->next_task_message_to_write_ = nullptr;
        this->on_finished_write_callback_.call();
      }
    }
  }

  this->read_mode();
  this->turn_off_rf_();
}

bool PN532SpiEmv::send_apdu_(const std::vector<uint8_t> &apdu, std::vector<uint8_t> &response) {
  std::vector<uint8_t> command;
  command.reserve(apdu.size() + 2);
  command.push_back(PN532_COMMAND_INDATAEXCHANGE);
  command.push_back(0x01);  // Single card support.
  command.insert(command.end(), apdu.begin(), apdu.end());

  if (!this->write_command_(command)) {
    ESP_LOGW(TAG, "Failed to send APDU command");
    return false;
  }

  if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response) || response.empty() || response[0] != 0x00) {
    ESP_LOGW(TAG, "APDU exchange failed");
    return false;
  }

  if (response.size() < 3)
    return false;

  response.erase(response.begin());
  response.erase(response.end() - 2, response.end());
  return true;
}

static bool parse_tlv_find_inner(const std::vector<uint8_t> &buffer, size_t start, size_t end, uint16_t needle,
                                 std::vector<uint8_t> &value) {
  size_t cursor = start;
  while (cursor < end) {
    TlvHeader header;
    if (!parse_tlv_header(buffer, cursor, header))
      return false;

    size_t value_start = cursor + header.header_len;
    size_t value_end = value_start + header.length;
    if (value_end > end)
      return false;

    if (header.tag == needle) {
      value.assign(buffer.begin() + value_start, buffer.begin() + value_end);
      return true;
    }

    if (header.length > 0 && is_template_tag(header.tag) &&
        parse_tlv_find_inner(buffer, value_start, value_end, needle, value)) {
      return true;
    }

    cursor = value_end;
  }
  return false;
}

bool PN532SpiEmv::parse_tlv_find_(const std::vector<uint8_t> &buffer, uint16_t needle, std::vector<uint8_t> &value) {
  return parse_tlv_find_inner(buffer, 0, buffer.size(), needle, value);
}

bool PN532SpiEmv::parse_track2_digits_(const std::vector<uint8_t> &track2, std::vector<uint8_t> &digits) {
  digits.clear();
  bool seen_separator = false;
  for (uint8_t byte : track2) {
    for (int shift : {4, 0}) {
      uint8_t nib = static_cast<uint8_t>((byte >> shift) & 0x0F);
      if (nib == 0x0D) {
        seen_separator = true;
        break;
      }
      if (nib == 0x0F)
        continue;
      if (nib > 9)
        return false;
      digits.push_back(nib);
      if (digits.size() > 19)
        return false;
    }
    if (seen_separator)
      break;
  }
  return seen_separator && digits.size() >= 8;
}

bool PN532SpiEmv::parse_track1_digits_(const std::vector<uint8_t> &track1, std::vector<uint8_t> &digits) {
  digits.clear();
  if (track1.empty() || static_cast<char>(track1.front()) != 'B')
    return false;

  size_t pos = 1;
  while (pos < track1.size() && static_cast<char>(track1[pos]) != '^') {
    char c = static_cast<char>(track1[pos++]);
    if (c < '0' || c > '9')
      return false;
    digits.push_back(static_cast<uint8_t>(c - '0'));
    if (digits.size() > 19)
      return false;
  }
  return pos < track1.size() && digits.size() >= 8;
}

bool PN532SpiEmv::parse_tag5a_digits_(const std::vector<uint8_t> &bcd, std::vector<uint8_t> &digits) {
  digits.clear();
  for (uint8_t byte : bcd) {
    uint8_t hi = static_cast<uint8_t>((byte >> 4) & 0x0F);
    uint8_t lo = static_cast<uint8_t>(byte & 0x0F);
    if (hi <= 9) {
      digits.push_back(hi);
    } else if (hi != 0x0F) {
      return false;
    }
    if (lo <= 9) {
      digits.push_back(lo);
    } else if (lo == 0x0F) {
      break;
    } else {
      return false;
    }
    if (digits.size() > 19)
      return false;
  }
  return digits.size() >= 8;
}

bool PN532SpiEmv::build_hashed_pan_ndef_(const std::vector<uint8_t> &digits, std::vector<uint8_t> &ndef_out) {
  if (digits.size() < 8 || digits.size() > 19)
    return false;

  std::string pan;
  pan.reserve(digits.size());
  for (uint8_t d : digits)
    pan.push_back(static_cast<char>('0' + d));

  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
#if defined(mbedtls_sha256_starts_ret)
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char *>(pan.data()), pan.size());
  if (!this->salt_.empty())
    mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char *>(this->salt_.data()), this->salt_.size());
  mbedtls_sha256_finish_ret(&ctx, digest);
#else
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(pan.data()), pan.size());
  if (!this->salt_.empty())
    mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(this->salt_.data()), this->salt_.size());
  mbedtls_sha256_finish(&ctx, digest);
#endif
  mbedtls_sha256_free(&ctx);

  char hex[65];
  for (int i = 0; i < 32; i++)
    std::sprintf(&hex[i * 2], "%02x", digest[i]);
  hex[64] = '\0';

  std::string payload = std::string("pan-sha256:") + hex;
  make_ndef_text_message(payload, ndef_out);
  return true;
}

std::vector<uint8_t> PN532SpiEmv::construct_pdol_payload_(const std::vector<uint8_t> &pdol) {
  std::vector<uint8_t> result;
  size_t cursor = 0;
  while (cursor < pdol.size()) {
    uint16_t tag = pdol[cursor++];
    if ((tag & 0x1F) == 0x1F) {
      if (cursor >= pdol.size())
        break;
      tag = static_cast<uint16_t>((tag << 8) | pdol[cursor++]);
    }
    if (cursor >= pdol.size())
      break;
    uint8_t len = pdol[cursor++];

    std::vector<uint8_t> value;
    switch (tag) {
      case 0x9F66:  // Terminal Transaction Qualifiers
        value = {0xF0, 0x20, 0x40, 0x00};
        break;
      case 0x9F02:  // Amount, Authorised (Numeric)
      case 0x9F03:  // Amount, Other (Numeric)
        value = {0x00, 0x00, 0x00, 0x00, 0x10, 0x00};
        break;
      case 0x9F1A:  // Terminal Country Code (Germany)
        value = {0x02, 0x76};
        break;
      case 0x5F2A:  // Transaction Currency Code (EUR)
        value = {0x09, 0x78};
        break;
      case 0x9A: {  // Transaction Date
        ESPTime now = ESPTime::from_epoch_local(::time(nullptr));
        value = {static_cast<uint8_t>((now.year - 2000) & 0xFF), static_cast<uint8_t>(now.month),
                 static_cast<uint8_t>(now.day_of_month)};
        break;
      }
      case 0x9F37:  // Unpredictable Number
        value = {0xB5, 0x43, 0xFF, 0x89};
        break;
      default:
        value.assign(len, 0x00);
        break;
    }

    if (value.size() < len)
      value.resize(len, 0x00);
    else if (value.size() > len)
      value.resize(len);

    result.insert(result.end(), value.begin(), value.end());
  }
  return result;
}

bool PN532SpiEmv::read_record_pan_(uint8_t record, uint8_t sfi, std::vector<uint8_t> &digits) {
  std::vector<uint8_t> apdu = {0x00, 0xB2, record, sfi, 0x00};
  std::vector<uint8_t> response;
  if (!this->send_apdu_(apdu, response))
    return false;

  std::vector<uint8_t> tag_data;
  if (this->parse_tlv_find_(response, 0x57, tag_data) && this->parse_track2_digits_(tag_data, digits))
    return true;

  if (this->parse_tlv_find_(response, 0x56, tag_data) && this->parse_track1_digits_(tag_data, digits))
    return true;

  if (this->parse_tlv_find_(response, 0x5A, tag_data) && this->parse_tag5a_digits_(tag_data, digits))
    return true;

  return false;
}

std::unique_ptr<nfc::NfcTag> PN532SpiEmv::read_emv_tag_(const std::vector<uint8_t> &uid) {
  std::vector<uint8_t> response;

  // 1. SELECT PPSE (2PAY.SYS.DDF01)
  static const std::vector<uint8_t> select_ppse = {
      0x00, 0xA4, 0x04, 0x00, 0x0E,
      0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
      0x00};

  if (!this->send_apdu_(select_ppse, response))
    return nullptr;

  std::vector<uint8_t> aid;
  if (!this->parse_tlv_find_(response, 0x4F, aid) || aid.empty()) {
    ESP_LOGD(TAG, "EMV AID not found");
    return nullptr;
  }

  // 2. SELECT application
  std::vector<uint8_t> select_aid = {0x00, 0xA4, 0x04, 0x00, static_cast<uint8_t>(aid.size())};
  select_aid.insert(select_aid.end(), aid.begin(), aid.end());
  select_aid.push_back(0x00);

  if (!this->send_apdu_(select_aid, response))
    return nullptr;

  std::vector<uint8_t> pdol;
  this->parse_tlv_find_(response, 0x9F38, pdol);
  std::vector<uint8_t> pdol_payload = this->construct_pdol_payload_(pdol);

  // 3. GET PROCESSING OPTIONS
  std::vector<uint8_t> gpo = {0x80, 0xA8, 0x00, 0x00, static_cast<uint8_t>(pdol_payload.size() + 2), 0x83,
                              static_cast<uint8_t>(pdol_payload.size())};
  gpo.insert(gpo.end(), pdol_payload.begin(), pdol_payload.end());
  gpo.push_back(0x00);

  if (!this->send_apdu_(gpo, response))
    return nullptr;

  std::vector<uint8_t> digits;
  std::vector<uint8_t> tag_data;
  if (this->parse_tlv_find_(response, 0x57, tag_data) && this->parse_track2_digits_(tag_data, digits)) {
    std::vector<uint8_t> ndef;
    if (this->build_hashed_pan_ndef_(digits, ndef)) {
      auto uid_copy = uid;
      return make_unique<nfc::NfcTag>(uid_copy, nfc::NFC_FORUM_TYPE_2, ndef);
    }
  }

  std::vector<uint8_t> afl;
  if (!this->parse_tlv_find_(response, 0x94, afl) || afl.size() < 4)
    return nullptr;

  size_t pos = 0;
  while (pos + 3 < afl.size()) {
    uint8_t sfi_byte = afl[pos++];
    uint8_t first_record = afl[pos++];
    uint8_t last_record = afl[pos++];
    pos++;  // skip offline auth byte
    uint8_t sfi = static_cast<uint8_t>((sfi_byte & 0xF8) | 0x04);

    for (uint8_t record = first_record; record <= last_record; ++record) {
      if (this->read_record_pan_(record, sfi, digits)) {
        std::vector<uint8_t> ndef;
        if (this->build_hashed_pan_ndef_(digits, ndef)) {
          auto uid_copy = uid;
          return make_unique<nfc::NfcTag>(uid_copy, nfc::NFC_FORUM_TYPE_2, ndef);
        }
      }
      yield();
    }
  }

  return nullptr;
}

}  // namespace pn532_spi_emv
}  // namespace esphome
