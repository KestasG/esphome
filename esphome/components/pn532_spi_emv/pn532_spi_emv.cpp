#include "pn532_spi_emv.h"

#include "esphome/components/nfc/nfc.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "esphome/core/time.h"

#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#include "mbedtls/sha256.h"

#include <cstdio>
#include <ctime>
#include <memory>

namespace esphome {
namespace pn532_spi_emv {

static const char *const TAG = "pn532.spi_emv";
static const uint8_t EMV_SFI_MASK = 0xF8;
static const uint8_t EMV_SFI_READ_CMD_BITS = 0x04;

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
    while (count-- != 0) {
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
  const std::string lang("en");
  const uint8_t status = static_cast<uint8_t>(lang.size() & 0x3F);
  const size_t payload_len = 1 + lang.size() + text.size();

  out.clear();
  out.reserve(3 + 1 + payload_len);
  out.push_back(0xD1);
  out.push_back(0x01);
  out.push_back(static_cast<uint8_t>(payload_len));
  out.push_back('T');
  out.push_back(status);
  out.insert(out.end(), lang.begin(), lang.end());
  out.insert(out.end(), text.begin(), text.end());
}

void PN532SpiEmv::setup() {
  ESP_LOGV(TAG, "Setting up PN532 SPI EMV reader");
  this->spi_setup();
  this->cs_->digital_write(false);
  delay(10);
  pn532::PN532::setup();
}

void PN532SpiEmv::dump_config() {
  pn532::PN532::dump_config();
  LOG_PIN("  CS Pin: ", this->cs_);
}

void PN532SpiEmv::set_busy_pin(GPIOPin *pin) {
  this->busy_pin_ = pin;
  if (this->busy_pin_ != nullptr) {
    this->busy_pin_->setup();
    this->busy_pin_->digital_write(false);
  }
}

std::unique_ptr<nfc::NfcTag> PN532SpiEmv::read_tag_(std::vector<uint8_t> &uid) {
  auto tag = pn532::PN532::read_tag_(uid);
  if (!tag)
    tag = std::make_unique<nfc::NfcTag>(uid);

  struct BusyGuard {
    explicit BusyGuard(GPIOPin *pin) : pin(pin) {
      if (this->pin != nullptr)
        this->pin->digital_write(true);
    }
    ~BusyGuard() {
      if (this->pin != nullptr)
        this->pin->digital_write(false);
    }
    GPIOPin *pin;
  } guard(this->busy_pin_);

  auto emv_tag = this->read_emv_tag_(uid);
  if (!emv_tag || !emv_tag->has_ndef_message())
    return tag;

  const auto &message = emv_tag->get_ndef_message();
  if (message == nullptr)
    return tag;

  auto ndef_copy = std::make_unique<nfc::NdefMessage>(*message);
  tag->set_ndef_message(std::move(ndef_copy));
  return tag;
}

bool PN532SpiEmv::is_read_ready() {
  this->enable();
  this->write_byte(0x02);
  bool ready = this->read_byte() == 0x01;
  this->disable();
  return ready;
}

bool PN532SpiEmv::write_data(const std::vector<uint8_t> &data) {
  this->enable();
  delay(2);
  this->write_byte(0x01);
  ESP_LOGV(TAG, "Writing data: %s", format_hex_pretty(data).c_str());
  this->write_array(data.data(), data.size());
  this->disable();
  return true;
}

bool PN532SpiEmv::read_data(std::vector<uint8_t> &data, uint8_t len) {
  if (this->read_ready_(true) != pn532::PN532ReadReady::READY)
    return false;

  this->enable();
  delay(2);
  this->write_byte(0x03);

  ESP_LOGV(TAG, "Reading data");

  data.resize(len);
  this->read_array(data.data(), len);
  this->disable();
  data.insert(data.begin(), 0x01);
  ESP_LOGV(TAG, "Read data: %s", format_hex_pretty(data).c_str());
  return true;
}

bool PN532SpiEmv::read_response(uint8_t command, std::vector<uint8_t> &data) {
  if (this->read_ready_(true) != pn532::PN532ReadReady::READY)
    return false;

  this->enable();
  delay(2);
  this->write_byte(0x03);

  std::vector<uint8_t> header(7);
  this->read_array(header.data(), header.size());

  ESP_LOGV(TAG, "Header data: %s", format_hex_pretty(header).c_str());

  if (header[0] != 0x00 && header[1] != 0x00 && header[2] != 0xFF)
    return false;

  bool valid_header = (static_cast<uint8_t>(header[3] + header[4]) == 0 && header[5] == 0xD5 &&
                       (header[6] == command + 1 || header[6] == command));

  if (!valid_header)
    return false;

  uint8_t full_len = header[3];
  uint8_t len = (full_len == 0) ? 0 : full_len - 1;

  data.resize(len + 1);
  this->read_array(data.data(), len + 1);
  this->disable();

  ESP_LOGV(TAG, "Response data: %s", format_hex_pretty(data).c_str());

  uint8_t checksum = header[5] + header[6];
  for (int i = 0; i < len - 1; i++)
    checksum += data[i];
  checksum = ~checksum + 1;

  if (data[len - 1] != checksum)
    return false;

  if (data[len] != 0x00)
    return false;

  data.erase(data.end() - 2, data.end());
  return true;
}

bool PN532SpiEmv::send_apdu_(const std::vector<uint8_t> &apdu, std::vector<uint8_t> &response) {
  std::vector<uint8_t> command;
  command.reserve(apdu.size() + 2);
  command.push_back(pn532::PN532_COMMAND_INDATAEXCHANGE);
  command.push_back(0x01);
  command.insert(command.end(), apdu.begin(), apdu.end());

  if (!this->write_command_(command))
    return false;

  std::vector<uint8_t> raw;
  if (!this->read_response(pn532::PN532_COMMAND_INDATAEXCHANGE, raw) || raw.empty() || raw[0] != 0x00)
    return false;

  if (raw.size() < 3)
    return false;

  uint8_t sw1 = raw[raw.size() - 2];
  uint8_t sw2 = raw[raw.size() - 1];
  if (sw1 != 0x90 || sw2 != 0x00)
    return false;

  response.assign(raw.begin() + 1, raw.end() - 2);
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

  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
#if defined(mbedtls_sha256_starts_ret)
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, digits.data(), digits.size());
  if (!this->salt_.empty())
    mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char *>(this->salt_.data()),
                              this->salt_.size());
  mbedtls_sha256_finish_ret(&ctx, digest);
#else
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, digits.data(), digits.size());
  if (!this->salt_.empty())
    mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(this->salt_.data()),
                          this->salt_.size());
  mbedtls_sha256_finish(&ctx, digest);
#endif
  mbedtls_sha256_free(&ctx);

  char hex[65];
  for (int i = 0; i < 32; i++)
    std::sprintf(&hex[i * 2], "%02x", digest[i]);
  hex[64] = '\0';

  make_ndef_text_message(std::string("pan-sha256:") + hex, ndef_out);
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
      case 0x9F66:
        value = {0xF0, 0x20, 0x40, 0x00};
        break;
      case 0x9F02:
      case 0x9F03:
        value = {0x00, 0x00, 0x00, 0x00, 0x10, 0x00};
        break;
      case 0x9F1A:
        value = {0x02, 0x76};
        break;
      case 0x5F2A:
        value = {0x09, 0x78};
        break;
      case 0x9A: {
        ESPTime now = ESPTime::from_epoch_local(::time(nullptr));
        value = {static_cast<uint8_t>((now.year - 2000) & 0xFF), static_cast<uint8_t>(now.month),
                 static_cast<uint8_t>(now.day_of_month)};
        break;
      }
      case 0x9F37:
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
  auto log_digits = [&](const char *source) {
    std::string pan;
    pan.reserve(digits.size());
    for (uint8_t d : digits)
      pan.push_back(static_cast<char>('0' + d));
    ESP_LOGD(TAG, "PAN digits (%s): %s", source, pan.c_str());
  };

  if (this->parse_tlv_find_(response, 0x57, tag_data) && this->parse_track2_digits_(tag_data, digits)) {
    log_digits("track2");
    return true;
  }

  if (this->parse_tlv_find_(response, 0x56, tag_data) && this->parse_track1_digits_(tag_data, digits)) {
    log_digits("track1");
    return true;
  }

  if (this->parse_tlv_find_(response, 0x5A, tag_data) && this->parse_tag5a_digits_(tag_data, digits)) {
    log_digits("tag5A");
    return true;
  }

  if (!digits.empty()) {
    ESP_LOGV(TAG, "Digits: %s", format_hex_pretty(digits).c_str());
  }

  return false;
}

std::unique_ptr<nfc::NfcTag> PN532SpiEmv::read_emv_tag_(const std::vector<uint8_t> &uid) {
  std::vector<uint8_t> response;

  static const std::vector<uint8_t> select_ppse = {
      0x00, 0xA4, 0x04, 0x00, 0x0E,
      0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
      0x00};

  if (!this->send_apdu_(select_ppse, response))
    return nullptr;

  std::vector<uint8_t> aid;
  if (!this->parse_tlv_find_(response, 0x4F, aid) || aid.empty())
    return nullptr;

  std::vector<uint8_t> select_aid = {0x00, 0xA4, 0x04, 0x00, static_cast<uint8_t>(aid.size())};
  select_aid.insert(select_aid.end(), aid.begin(), aid.end());
  select_aid.push_back(0x00);

  if (!this->send_apdu_(select_aid, response))
    return nullptr;

  std::vector<uint8_t> pdol;
  this->parse_tlv_find_(response, 0x9F38, pdol);
  std::vector<uint8_t> pdol_payload = this->construct_pdol_payload_(pdol);

  std::vector<uint8_t> gpo = {0x80, 0xA8, 0x00, 0x00, static_cast<uint8_t>(pdol_payload.size() + 2), 0x83,
                              static_cast<uint8_t>(pdol_payload.size())};
  gpo.insert(gpo.end(), pdol_payload.begin(), pdol_payload.end());
  gpo.push_back(0x00);

  if (!this->send_apdu_(gpo, response))
    return nullptr;

  std::vector<uint8_t> digits;
  std::vector<uint8_t> tag_data;
  auto log_digits = [&](const char *source) {
    std::string pan;
    pan.reserve(digits.size());
    for (uint8_t d : digits)
      pan.push_back(static_cast<char>('0' + d));
    ESP_LOGD(TAG, "PAN digits (%s): %s", source, pan.c_str());
  };

  if (this->parse_tlv_find_(response, 0x57, tag_data) && this->parse_track2_digits_(tag_data, digits)) {
    log_digits("track2");
    std::vector<uint8_t> ndef;
    if (this->build_hashed_pan_ndef_(digits, ndef)) {
      auto uid_copy = uid;
      return std::make_unique<nfc::NfcTag>(uid_copy, std::string("EMV"), ndef);
    }
  }

  if (this->parse_tlv_find_(response, 0x56, tag_data) && this->parse_track1_digits_(tag_data, digits)) {
    log_digits("track1");
    std::vector<uint8_t> ndef;
    if (this->build_hashed_pan_ndef_(digits, ndef)) {
      auto uid_copy = uid;
      return std::make_unique<nfc::NfcTag>(uid_copy, std::string("EMV"), ndef);
    }
  }

  if (this->parse_tlv_find_(response, 0x5A, tag_data) && this->parse_tag5a_digits_(tag_data, digits)) {
    log_digits("tag5A");
    std::vector<uint8_t> ndef;
    if (this->build_hashed_pan_ndef_(digits, ndef)) {
      auto uid_copy = uid;
      return std::make_unique<nfc::NfcTag>(uid_copy, std::string("EMV"), ndef);
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
    pos++;
    uint8_t sfi = static_cast<uint8_t>((sfi_byte & EMV_SFI_MASK) | EMV_SFI_READ_CMD_BITS);

    for (uint8_t record = first_record; record <= last_record; ++record) {
      if (this->read_record_pan_(record, sfi, digits)) {
        
        std::vector<uint8_t> ndef;
        if (this->build_hashed_pan_ndef_(digits, ndef)) {          
          auto uid_copy = uid;
          return std::make_unique<nfc::NfcTag>(uid_copy, std::string("EMV"), ndef);
        }
      }
      yield();
    }
  }

  return nullptr;
}

}  // namespace pn532_spi_emv
}  // namespace esphome
