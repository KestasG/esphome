#include <memory>

#include "pn532.h"
#include "esphome/core/log.h"
#include "esphome/core/time.h"
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include <cstdio>
#include <ctime>

namespace esphome {
namespace pn532 {

// EMV reader implementation notes
// --------------------------------
//  - EMVCo: "EMV Contactless Specifications for Payment Systems", Book A (Architecture)
//           and Book C-2 (Kernel 2, Visa/Mastercard) – defines the APDU flow used below.
//           (https://www.emvco.com/document-search/?filteredby=Contactless)
//  - EMVCo: "EMV Integrated Circuit Card Specifications for Payment Systems", Book 3 –
//           covers PDOL construction, AFL layout, and READ RECORD semantics.
//           (https://www.emvco.com/document-search/?filteredby=Integrated%20Circuit%20Card)
//  - ISO/IEC 7816-4: Command/response structures and BER-TLV encoding rules.
//           (https://www.iso.org/standard/80182.html)
//  - NXP AN133910: "PN532 Implementation Guidelines" – timing hints and host interface details.
//           (https://www.nxp.com/docs/en/application-note/AN133910.pdf)
//  - NXP AN10833: "MIFARE Type Identification Procedure" – SAK to product mappings (Table 5).
//           (https://www.nxp.com/docs/en/application-note/AN10833.pdf)
//  - NXP PN532 User Manual (Doc. 141520): §7.3.2 "InDataExchange" framing used by sendAPDU().
//           (https://www.nxp.com/docs/en/user-guide/141520.pdf)

static const char *const TAG = "pn532.mifare_plus";

namespace {
// RAII helper guarding the optional busy pin. Cards that require longer APDU sequences benefit from
// driving a "busy" indicator so the rest of the automation stack can gate concurrent operations.
class BusyGuard {
 public:
  explicit BusyGuard(GPIOPin *pin) : pin_(pin) {
    if (this->pin_ != nullptr)
      this->pin_->digital_write(true);
  }
  ~BusyGuard() {
    if (this->pin_ != nullptr)
      this->pin_->digital_write(false);
  }

 private:
  GPIOPin *pin_{nullptr};
};

// EMV tag identifiers (EMV Book 3, Annex A; EMV Contactless Book C-2, §6).
constexpr uint8_t kEmvTagAid = 0x4F;
constexpr uint16_t kEmvTagPdol = 0x9F38;
constexpr uint16_t kEmvTagCommand = 0x83;
constexpr uint16_t kEmvTagTrack2 = 0x57;
constexpr uint16_t kEmvTagTrack1 = 0x56;
constexpr uint16_t kEmvTagPan = 0x5A;
constexpr uint16_t kEmvTagAfl = 0x94;
constexpr uint16_t kEmvTagFciTemplate = 0x6F;
constexpr uint16_t kEmvTagFciProprietaryTemplate = 0xA5;
constexpr uint16_t kEmvTagFciIssuerDiscretionary = 0xBF0C;
constexpr uint16_t kEmvTagApplicationTemplate = 0x61;
constexpr uint16_t kEmvTagResponseTemplateFormat2 = 0x77;
constexpr uint16_t kEmvTagRecordTemplate = 0x70;
}  // namespace


std::vector<uint8_t> parse_nibbles(std::vector<uint8_t> &data, uint8_t terminator){

    std::vector<uint8_t> result;
    uint8_t pos = 0;
    while (pos < data.size()) {
      uint8_t hi_nibble = data[pos] >> 4;
      uint8_t lo_nibble = data[pos] & 0b00001111;
      if (hi_nibble == terminator)
        break;
      result.push_back(hi_nibble);
      if (lo_nibble == terminator)
        break;
      result.push_back(lo_nibble);
      pos++;
    }
    if(pos > 10 || pos < 3) {//PAN is 8 to 19 digits 
      ESP_LOGW(TAG, "Error resolving PAN from nibbles");
      ESP_LOGV(TAG, "  Raw data: %s", format_hex_pretty(data).c_str());  
      return {};
    }
    ESP_LOGV(TAG, "Found PAN: %s", format_hex_pretty(result).c_str());
    return result;
}
std::vector<uint8_t> parse_track2(std::vector<uint8_t> &data ){
    /* 
    Track 2 data https://emvlab.org/emvtags/show/t57/
    record contents:
    Primary Account Number (n, var. up to 19)
    Field Separator (Hex 'D') (b)
    Expiration Date (YYMM) (n 4)
    Service Code (n 3)
    Discretionary Data (defined by individual payment systems) (n, var.)
    Pad with one Hex 'F' if needed to ensure whole bytes (b)
    */
  return parse_nibbles(data, 0x0D);  
}

std::vector<uint8_t> parse_pan(std::vector<uint8_t> &data){
    /*     
    record contents:
    Primary Account Number (n, var. up to 19)    
    Pad with one Hex 'F' if needed to ensure whole bytes (b)
    */
  return parse_nibbles(data, 0x0F);
}


std::vector<uint8_t> parse_track1(std::vector<uint8_t> &data){
      /* 
    Track 1 data https://en.wikipedia.org/wiki/ISO/IEC_7813
    FC : Format code "B" (The format described here. Format "A" is reserved for proprietary use.)
    PAN : Payment card number 4400664987366029, up to 19 digits
    FS : Separator "^"
    .....
    */       
    uint8_t pos = 0;
    if(data.size() == 0 || data[pos++] != 'B'){
      ESP_LOGW(TAG, "Error resolving PAN from Track1");
      ESP_LOGV(TAG, "  Raw data: %s", format_hex_pretty(data).c_str());  
      return {};
    }

    std::vector<uint8_t> result;
    while (pos < data.size()) {
      uint8_t digit = data[pos];
      if(digit == '^')//end of PAN
        break;
      if(digit < '0' || digit > '9'){
        ESP_LOGW(TAG, "Error resolving PAN from Track1");
        ESP_LOGV(TAG, "  Raw data: %s", format_hex_pretty(data).c_str());  
        return {};
      }
      result.push_back(digit - '0');      
      pos++;
    }
    if(pos >= data.size() || pos > 20) {//'^' was not found or PAN longer than 19 digits
    ESP_LOGW(TAG, "PAN not found in Track1");
    ESP_LOGV(TAG, "  Raw data: %s", format_hex_pretty(data).c_str());  
      return {};
    }
    ESP_LOGV(TAG, "Found PAN: %s", format_hex_pretty(result).c_str());
    return result;
}


std::unique_ptr<nfc::NfcTag> PN532::read_mifare_plus_tag_(std::vector<uint8_t> &uid) {
  BusyGuard guard(this->busy_pin_);

  std::vector<uint8_t> data;
  // pages 3 to 6 contain various info we are interested in -- do one read to grab it all
  if (!this->read_mifare_plus_bytes_(3, nfc::MIFARE_ULTRALIGHT_PAGE_SIZE * nfc::MIFARE_ULTRALIGHT_READ_SIZE, data)) {
    ESP_LOGW(TAG, "Mifare Plus/Desfire. Failed reading as EMV");
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }

  return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2, data);
}

// (A) Hex encoder for logging
static inline std::string to_hex(const uint8_t *buf, size_t len) {
  char out[129]; // enough for 64 bytes if ever needed
  size_t p = 0;
  for (size_t i = 0; i < len; i++) {
    std::sprintf(out + p, "%02x", buf[i]);
    p += 2;
  }
  out[p] = '\0';
  return std::string(out);
}

// Build NDEF Text message from given text
static inline void make_ndef_text_message(const std::string &text, std::vector<uint8_t> &out) {
  out.clear();
  const char *type_T = "T";
  const std::string lang = "en";   // language code

  // Payload: [status][lang][text]
  const uint8_t status = static_cast<uint8_t>(lang.size() & 0x3F);
  const size_t payload_len = 1 + lang.size() + text.size();

  if (payload_len > 255) {
    // Truncate text to fit SR record
    const size_t max_text = 255 - 1 - lang.size();
    return make_ndef_text_message(text.substr(0, max_text), out);
  }

  const uint8_t MB = 0x80;
  const uint8_t ME = 0x40;
  const uint8_t SR = 0x10;
  const uint8_t TNF_WK = 0x01;  // Well-known
  const uint8_t header = MB | ME | SR | TNF_WK;  // 0xD1

  out.reserve(3 + 1 + payload_len);
  out.push_back(header);
  out.push_back(0x01);                      // TYPE LENGTH
  out.push_back(static_cast<uint8_t>(payload_len));
  out.push_back(static_cast<uint8_t>(type_T[0]));   // 'T'
  out.push_back(status);
  out.insert(out.end(), lang.begin(), lang.end());
  out.insert(out.end(), text.begin(), text.end());
}

// TLV helper used by find_tag_(); keeps the BER parsing logic in one place.
struct TlvHeader {
  uint16_t tag;
  size_t length;
  size_t header_len;  // number of bytes consumed by tag + length fields
};

// Minimal BER-TLV header parser (ISO/IEC 7816-4, Clause 5.2). Only handles short-form tags/lengths
// required by the EMV templates this component consumes.
static bool read_tlv_header_(const std::vector<uint8_t> &buffer, size_t offset, TlvHeader &out) {
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
  if (len_byte & 0x80) {
    uint8_t count = len_byte & 0x7F;
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

static inline bool is_emv_template_tag_(uint16_t tag) {
  return tag == kEmvTagFciTemplate || tag == kEmvTagFciProprietaryTemplate ||
         tag == kEmvTagFciIssuerDiscretionary || tag == kEmvTagApplicationTemplate ||
         tag == kEmvTagResponseTemplateFormat2 || tag == kEmvTagRecordTemplate;
}

static std::vector<uint8_t> find_tag_(std::vector<uint8_t> &ber_data, uint16_t tag_to_find);
static std::vector<uint8_t> construct_pdol_data_(const std::vector<uint8_t> &pdol);

// Hash the PAN digits using SHA-256 (salted) and emit an NDEF text record. This mirrors typical
// tokenisation guidance: PAN must never be published in clear text. (See PCI DSS & EMVCo bulletins.)
static inline bool sha256_bytes_salted(const uint8_t *pan_digits, size_t num_digits,
                                       const std::string &salt,
                                       std::vector<uint8_t> &ndef_out) {
  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);

#if defined(mbedtls_sha256_starts_ret)
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, pan_digits, num_digits);
  if (!salt.empty()) {
    mbedtls_sha256_update_ret(&ctx,
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size());
  }
  mbedtls_sha256_finish_ret(&ctx, digest);
#else
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, pan_digits, num_digits);
  if (!salt.empty()) {
    mbedtls_sha256_update(&ctx,
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size());
  }
  mbedtls_sha256_finish(&ctx, digest);
#endif

  mbedtls_sha256_free(&ctx);

  // Convert digest to hex
  char hexbuf[65];
  for (int i = 0; i < 32; i++) {
    sprintf(&hexbuf[i * 2], "%02x", digest[i]);
  }
  hexbuf[64] = '\0';

  std::string text = std::string("pan-sha256:") + hexbuf;

  // Build valid NDEF Text record
  make_ndef_text_message(text, ndef_out);

  return true;
}

// (C) Extract digit nibbles (0..9) from Track-2-equivalent (9F6B) bytes until 'D' nibble (0xD).
//     Ignores 0xF padding. Enforces 8..19 digits. Returns true on success.
static bool pan_from_track2_nibbles_(const std::vector<uint8_t>& track2_bytes,
                                     uint8_t pan_digits[19], size_t &num_digits) {
  num_digits = 0;
  bool found_term = false;
  auto push = [&](uint8_t nib) -> bool {
    if (nib == 0x0D) { found_term = true; return true; }     // 'D' separator
    if (nib == 0x0F) return true;                            // padding nibble
    if (nib <= 9) {
      if (num_digits < 19) {
        pan_digits[num_digits++] = nib;
        return true;
      }
      return false;
    }
    // invalid non-digit nibble before terminator
    return false;
  };
  for (size_t i = 0; i < track2_bytes.size() && !found_term; ++i) {
    uint8_t b = track2_bytes[i];
    if (!push((b >> 4) & 0x0F)) return false;
    if (found_term) break;
    if (!push(b & 0x0F))        return false;
  }
  if (!found_term) return false;
  if (num_digits < 8 || num_digits > 19) return false;
  return true;
}

// (D) Extract PAN from Track-1 (tag 56) ASCII: digits until '^'
static bool pan_from_track1_ascii_(const std::vector<uint8_t>& track1_bytes,
                                   uint8_t pan_digits[19], size_t &num_digits) {
  num_digits = 0;
  for (size_t i = 0; i < track1_bytes.size(); ++i) {
    char c = static_cast<char>(track1_bytes[i]);
    if (c == '^') break;
    if (c >= '0' && c <= '9') {
      if (num_digits < 19) {
        pan_digits[num_digits++] = static_cast<uint8_t>(c - '0');
      } else {
        return false;
      }
    } else if (c == ';' || c == 'B') {
      // Skip common sentinels if present at start
      continue;
    } else if (c == ' ') {
      continue;
    } else if (c == '\0') {
      break;
    } else {
      // Non-digit before delimiter – tolerate, but only if we already have some digits
      // If you want to be strict, return false here.
      continue;
    }
  }
  if (num_digits < 8 || num_digits > 19) return false;
  return true;
}

// (E) Extract PAN from 5A (BCD): nibbles 0..9; ignore trailing 0xF
static bool pan_from_tag5a_bcd_(const std::vector<uint8_t>& pan_bcd,
                                uint8_t pan_digits[19], size_t &num_digits) {
  num_digits = 0;
  for (size_t i = 0; i < pan_bcd.size(); ++i) {
    uint8_t hi = (pan_bcd[i] >> 4) & 0x0F;
    uint8_t lo = pan_bcd[i] & 0x0F;
    if (hi <= 9) {
      if (num_digits < 19) pan_digits[num_digits++] = hi;
      else return false;
    }
    else if (hi != 0x0F) return false;
    if (lo <= 9) {
      if (num_digits < 19) pan_digits[num_digits++] = lo;
      else return false;
    }
    else if (lo == 0x0F) break;      // padding nibble indicates end
    else return false;
  }
  if (num_digits < 8 || num_digits > 19) return false;
  return true;
}

bool PN532::read_mifare_plus_bytes_(uint8_t start_page, uint16_t num_bytes, std::vector<uint8_t> &data) {
  (void) start_page;
  (void) num_bytes;
  std::vector<uint8_t> apdu_response;

  // EMV contactless flow (simplified for read-only use, cf. EMV Contactless Book C-2 §6):
  //   1. SELECT the PPSE directory (2PAY.SYS.DDF01) to learn which payment application AID to use.
  //   2. SELECT the returned AID to retrieve the application descriptor and Processing Options Data Object List (PDOL).
  //   3. Build the PDOL payload and issue GET PROCESSING OPTIONS (GPO) to obtain the Application File Locator (AFL).
  //   4. Walk the AFL entries, READ RECORD for each and extract Track / PAN data.
  // Every APDU is retried a few times: real cards are timing sensitive and intermittently reject requests.

  // Step 1: SELECT PPSE (2PAY.SYS.DDF01) to find the payment application directory.
  std::vector<uint8_t> command_apdu = {
    0x00, 0xa4, 0x04, 0x00,
    0x0e,
    0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31,
    0x00
  };

  ESP_LOGV(TAG, "Sending request to read file");
  if (!sendAPDU(command_apdu, apdu_response)) return false;

  auto adf_name = find_tag_(apdu_response, kEmvTagAid);
  if (adf_name.empty()) {
    ESP_LOGD(TAG, "AID retrieval failed");
    return false;
  }
  ESP_LOGV(TAG, "Found ADF name: %s", format_hex_pretty(adf_name).c_str());

  // Step 2: SELECT the specific application using the AID discovered above.
  command_apdu = {0x00, 0xa4, 0x04, 0x00};
  command_apdu.push_back(adf_name.size());
  command_apdu.insert(std::end(command_apdu), std::begin(adf_name), std::end(adf_name));
  command_apdu.push_back(0x00);

  ESP_LOGV(TAG, "Sending request to select application and get PDOL #1");
  if (!sendAPDU(command_apdu, apdu_response)) {
    ESP_LOGV(TAG, "Sending request to select application and get PDOL #2");
    if (!sendAPDU(command_apdu, apdu_response)) {
      ESP_LOGV(TAG, "Sending request to select application and get PDOL #3");
      if (!sendAPDU(command_apdu, apdu_response)) {
        ESP_LOGD(TAG, "Failed request to select application and get PDOL. Giving up.");
        return false;
      }
    }
  }

  auto pdol = find_tag_(apdu_response, kEmvTagPdol);
  ESP_LOGV(TAG, "Found PDOL: %s", format_hex_pretty(pdol).c_str());

  // Step 3: Issue GET PROCESSING OPTIONS with a PDOL payload to obtain AIP/AFL.
  command_apdu = {0x80, 0xa8, 0x00, 0x00};
  auto pdol_data = construct_pdol_data_(pdol);
  command_apdu.push_back(pdol_data.size() + 2);
  command_apdu.push_back(kEmvTagCommand);
  command_apdu.push_back(pdol_data.size());
  command_apdu.insert(std::end(command_apdu), std::begin(pdol_data), std::end(pdol_data));
  command_apdu.push_back(0x00);

  ESP_LOGV(TAG, "Sending request for AFL");
  if (!sendAPDU(command_apdu, apdu_response)) {
    ESP_LOGV(TAG, "Sending request for AFL retry ");
    if (!sendAPDU(command_apdu, apdu_response)) {
      ESP_LOGV(TAG, "Sending request for AFL retry #2");
      if (!sendAPDU(command_apdu, apdu_response)) {
        ESP_LOGD(TAG, "Sending request for AFL failed 3 times. Giving up.");
        return false;
      }
    }
  }

  // ---- Case 1: Some cards return Track-2 (9F6B) in GPO response ------------
  if (auto track2_gpo = find_tag_(apdu_response, kEmvTagTrack2); !track2_gpo.empty()) {
    ESP_LOGV(TAG, "Found Track 2 Equivalent (9F6B) in GPO response: %s",
             format_hex_pretty(track2_gpo).c_str());
    uint8_t pan_digits[19];
    size_t num_pan_digits = 0;
    if (pan_from_track2_nibbles_(track2_gpo, pan_digits, num_pan_digits) &&
        sha256_bytes_salted(pan_digits, num_pan_digits, this->get_salt(), data)) {
      ESP_LOGV(TAG, "Returning salted PAN hash derived from GPO response");
      return true;
    }
  }

  // Step 4: Follow the AFL to READ RECORD entries and harvest account data.
  auto afl = find_tag_(apdu_response, kEmvTagAfl);
  ESP_LOGV(TAG, "Found AFL: %s", format_hex_pretty(afl).c_str());
  if (afl.size() < 4 || (afl.size() % 4) != 0) {
    ESP_LOGD(TAG, "Invalid AFL found");
    ESP_LOGV(TAG, "  AFL payload: %s", format_hex_pretty(afl).c_str());
    return false;
  }

  uint8_t pos = 0;
  while (pos + 3 < afl.size()) {
    // AFL entries are 4 bytes: [SFI|0x04][first record][last record][offline auth info].
    uint8_t sfi_byte = afl[pos++];
    uint8_t first_record = afl[pos++];
    uint8_t last_record = afl[pos++];
    pos++;  // Skip "number of records for offline authentication" byte.
    uint8_t read_record_p2 = static_cast<uint8_t>((sfi_byte & 0b11111000) | 0x04);

    for (uint8_t record = first_record; record <= last_record; ++record) {
      command_apdu = {0x00, 0xB2, record, read_record_p2, 0x00};
      ESP_LOGV(TAG, "Sending SFI read request");
      if (sendAPDU(command_apdu, apdu_response)) {
        // Try the EMV data elements in order of fidelity: Track-2 equivalent, Track-1, then PAN.
        // ---- Try 9F6B (Track-2 equiv, BCD nibbles) -------------------------
        if (auto track2_record = find_tag_(apdu_response, kEmvTagTrack2); !track2_record.empty()) {
          uint8_t pan_digits[19];
          size_t num_pan_digits = 0;
          if (pan_from_track2_nibbles_(track2_record, pan_digits, num_pan_digits) &&
              sha256_bytes_salted(pan_digits, num_pan_digits, this->get_salt(), data)) {            
            return true;
          }
        }

        // ---- Try 56 (Track-1, ASCII) --------------------------------------
        if (auto track1_record = find_tag_(apdu_response, kEmvTagTrack1); !track1_record.empty()) {
          uint8_t pan_digits[19];
          size_t num_pan_digits = 0;
          if (pan_from_track1_ascii_(track1_record, pan_digits, num_pan_digits) &&
              sha256_bytes_salted(pan_digits, num_pan_digits, this->get_salt(), data)) {            
            return true;
          }
        }

        // ---- Try 5A (PAN, BCD) --------------------------------------------
        if (auto pan_tag = find_tag_(apdu_response, kEmvTagPan); !pan_tag.empty()) {
          uint8_t pan_digits[19];
          size_t num_pan_digits = 0;
          if (pan_from_tag5a_bcd_(pan_tag, pan_digits, num_pan_digits) &&
              sha256_bytes_salted(pan_digits, num_pan_digits, this->get_salt(), data)) {            
            return true;
          }
        }

      } else {
        ESP_LOGV(TAG, "Failed SFI read request");
      }
      yield();  // Allow the ESPHome scheduler to run between APDU bursts.
    }
  }

  ESP_LOGD(TAG, "EMV READING FAILED !!!");
  return false;
}

// Helper wrapping PN532 "InDataExchange" (PN532 User Manual, Doc 141520 §7.3.2 –
// https://www.nxp.com/docs/en/user-guide/141520.pdf). Converts ISO/IEC 7816 APDUs to the
// PN532 frame format and removes the status byte / SW1 SW2 trailer from the response.
bool PN532::sendAPDU(std::vector<uint8_t> &apdu, std::vector<uint8_t> &response) {
  // construct command
  std::vector<uint8_t> command({
      PN532_COMMAND_INDATAEXCHANGE,
      0x01  // nTag Working with single card only supported by the framework
  });
  command.insert(command.end(), apdu.begin(), apdu.end());

  if (!this->write_command_(command)) {
    ESP_LOGD(TAG, "write command from sendAPDU failed");
    return false;
  }

  // PN532 prepends a status byte (0x00 == success) before the APDU payload.
  if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response) || response[0] != 0x00) {
    ESP_LOGD(TAG, "read response from sendAPDU failed");    
    return false;    
  }

  ESP_LOGV(TAG, "Data read: %s", format_hex(response).c_str());

  if (response[response.size() - 1] != 0x00 || response[response.size() - 2] != 0x90) {
    // full list of error codes https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
    ESP_LOGD(TAG, "APDU command returned error: %s", format_hex(&response.data()[response.size() - 2], 2).c_str());
    return false;
  }
  // Remove PN532 framing: drop leading status byte and trailing SW1/SW2 status words.
  response = {response.begin() + 1, response.end() - 2};
  return true;
}

// Builds the PDOL data payload used in the GET PROCESSING OPTIONS command. PDOL (9F38) is encoded
// as a sequence of tag-length descriptors (no values), so we synthesise plausible defaults for the
// most common tags and pad with zeroes for everything else.
// Synthesise PDOL values as per EMV Book 3 Annex C (Terminal provided data).
static std::vector<uint8_t> construct_pdol_data_(const std::vector<uint8_t> &pdol) {
  if (pdol.size() < 2)
    return {};

  std::vector<uint8_t> result;
  size_t cursor = 0;
  while (cursor < pdol.size()) {
    if (cursor >= pdol.size())
      break;

    uint16_t tag = pdol[cursor++];
    if ((tag & 0x1F) == 0x1F) {
      if (cursor >= pdol.size())
        break;
      tag = static_cast<uint16_t>((tag << 8) + pdol[cursor++]);
    }

    if (cursor >= pdol.size())
      break;
    uint8_t len = pdol[cursor++];

    std::vector<uint8_t> tag_value;
    switch (tag) {
      case 0x9F66:  // Terminal Transaction Qualifiers (capabilities advertised by reader)
        tag_value = {0xF0, 0x20, 0x40, 0x00};
        break;
      case 0x9F02:  // Amount, Authorised (Numeric) – purchase amount in minor units
      case 0x9F03:  // Amount, Other (Numeric) – cashback amount, rarely used here
        tag_value = {0x00, 0x00, 0x00, 0x00, 0x10, 0x00};
        break;
      case 0x9F1A:  // Terminal Country Code (ISO numeric)
        tag_value = {0x01, 0xB8};  // Germany (276){0x02, 0x76};
        break;
      case 0x5F2A:  // Transaction Currency Code (ISO numeric)
        tag_value = {0x03, 0xD2};  // EUR (978){0x09, 0x78}; 
        break;
      case 0x9A: {  // Transaction Date (YYMMDD, BCD)
        auto to_bcd = [](uint8_t v) -> uint8_t { return uint8_t(((v / 10) << 4) | (v % 10)); };

        ESPTime now = ESPTime::from_epoch_local(static_cast<uint32_t>(::time(nullptr)));
        uint8_t yy = now.is_valid() ? uint8_t(now.year % 100) : 0;
        uint8_t mm = now.is_valid() ? now.month : 0;
        uint8_t dd = now.is_valid() ? now.day_of_month : 0;

        tag_value.push_back(to_bcd(yy));
        tag_value.push_back(to_bcd(mm));  // 01..12 -> 0x01..0x12
        tag_value.push_back(to_bcd(dd));  // 01..31 -> 0x01..0x31
        break;
      }

      case 0x9F37:  // Unpredictable Number (nonce supplied by terminal)
        tag_value = {0xB5, 0x43, 0xFF, 0x89};
        break;
      case 0x95: //TVR
        tag_value = {0x00, 0x00, 0x00, 0x00, 0x00};
        break;
      case 0x9C: //TCC
        tag_value = {0x00};
        break;
      default:
        // Unknown tags get zero padding; this keeps the GPO payload structurally valid.
        tag_value.resize(len, 0x00);
        break;
    }

    if (tag_value.size() < len) {
      tag_value.resize(len, 0x00);
    } else if (tag_value.size() > len) {
      tag_value.resize(len);
    }

    result.insert(result.end(), tag_value.begin(), tag_value.end());
  }

  return result;
}

// Depth-first search for a specific tag inside a BER-TLV buffer. Template tags are traversed to
// mirror the nesting used by EMV records (FCI, record template, discretionary templates, ...).
static std::vector<uint8_t> find_tag_(std::vector<uint8_t> &ber_data, uint16_t tagToFind) {
  // Walk BER-TLV structures depth-first (EMV Book 3 Annex A). Template tags recurse into nested TLVs.
  size_t cursor = 0;
  while (cursor < ber_data.size()) {
    TlvHeader header;
    if (!read_tlv_header_(ber_data, cursor, header))
      return {};

    size_t value_start = cursor + header.header_len;
    if (value_start > ber_data.size() || value_start + header.length > ber_data.size())
      return {};

    std::vector<uint8_t> tag_value(ber_data.begin() + value_start,
                                   ber_data.begin() + value_start + header.length);

    if (header.tag == tagToFind) {
      return tag_value;
    }

    if (is_emv_template_tag_(header.tag)) {
      auto nested = find_tag_(tag_value, tagToFind);
      if (!nested.empty()) {
        return nested;
      }
    }

    cursor = value_start + header.length;
  }
  return {};
}

}  // namespace pn532
}  // namespace esphome
