#include <memory>

#include "pn532.h"
#include "esphome/core/log.h"
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

namespace esphome {
namespace pn532 {

static const char *const TAG = "pn532.mifare_plus";


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
      ESP_LOGW(TAG, "Error resolving PAN from nibbles: %s", format_hex_pretty(data).c_str());  
      return {};
    }
    ESP_LOGD(TAG, "Found PAN: %s", format_hex_pretty(result).c_str());
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
      ESP_LOGW(TAG, "Error resolving PAN from Track1: %s", format_hex_pretty(data).c_str());  
      return {};
    }

    std::vector<uint8_t> result;
    while (pos < data.size()) {
      uint8_t digit = data[pos];
      if(digit == '^')//end of PAN
        break;
      if(digit < '0' || digit > '9'){
        ESP_LOGW(TAG, "Error resolving PAN from Track1: %s", format_hex_pretty(data).c_str());  
        return {};
      }
      result.push_back(digit - '0');      
      pos++;
    }
    if(pos >= data.size() || pos > 20) {//'^' was not found or PAN longer than 19 digits
      ESP_LOGW(TAG, "PAN not found in Track1: %s", format_hex_pretty(data).c_str());  
      return {};
    }
    ESP_LOGD(TAG, "Found PAN: %s", format_hex_pretty(result).c_str());
    return result;
}


std::unique_ptr<nfc::NfcTag> PN532::read_mifare_plus_tag_(std::vector<uint8_t> &uid) {
  std::vector<uint8_t> data;
  // pages 3 to 6 contain various info we are interested in -- do one read to grab it all
  if (!this->read_mifare_plus_bytes_(3, nfc::MIFARE_ULTRALIGHT_PAGE_SIZE * nfc::MIFARE_ULTRALIGHT_READ_SIZE, data)) {
    ESP_LOGD(TAG, "Mifare Plus/Desfire. Failed reading as EMV");
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

// Compute salted SHA-256 of buf+salt and directly return as NDEF message
static inline bool sha256_bytes_salted(const uint8_t *buf, size_t len,
                                       const std::string &salt,
                                       std::vector<uint8_t> &ndef_out) {
  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);

#if defined(mbedtls_sha256_starts_ret)
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, buf, len);
  if (!salt.empty()) {
    mbedtls_sha256_update_ret(&ctx,
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size());
  }
  mbedtls_sha256_finish_ret(&ctx, digest);
#else
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, buf, len);
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

  // Prefix the text so you can distinguish it
  std::string text = std::string("pan-sha256:") + hexbuf;

  // Build valid NDEF Text record
  make_ndef_text_message(text, ndef_out);

  return true;
}

// (C) Extract digit nibbles (0..9) from Track-2-equivalent (9F6B) bytes until 'D' nibble (0xD).
//     Ignores 0xF padding. Enforces 8..19 digits. Returns true on success.
static bool pan_from_track2_nibbles_(const std::vector<uint8_t>& t2, uint8_t digits[19], size_t &dlen) {
  dlen = 0;
  bool found_term = false;
  auto push = [&](uint8_t nib) -> bool {
    if (nib == 0x0D) { found_term = true; return true; }     // 'D' separator
    if (nib == 0x0F) return true;                            // padding nibble
    if (nib <= 9) { if (dlen < 19) { digits[dlen++] = nib; return true; } else return false; }
    // invalid non-digit nibble before terminator
    return false;
  };
  for (size_t i = 0; i < t2.size() && !found_term; ++i) {
    uint8_t b = t2[i];
    if (!push((b >> 4) & 0x0F)) return false;
    if (found_term) break;
    if (!push(b & 0x0F))        return false;
  }
  if (!found_term) return false;
  if (dlen < 8 || dlen > 19) return false;
  return true;
}

// (D) Extract PAN from Track-1 (tag 56) ASCII: digits until '^'
static bool pan_from_track1_ascii_(const std::vector<uint8_t>& t1, uint8_t digits[19], size_t &dlen) {
  dlen = 0;
  for (size_t i = 0; i < t1.size(); ++i) {
    char c = static_cast<char>(t1[i]);
    if (c == '^') break;
    if (c >= '0' && c <= '9') {
      if (dlen < 19) digits[dlen++] = static_cast<uint8_t>(c - '0');
      else return false;
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
  if (dlen < 8 || dlen > 19) return false;
  return true;
}

// (E) Extract PAN from 5A (BCD): nibbles 0..9; ignore trailing 0xF
static bool pan_from_tag5a_bcd_(const std::vector<uint8_t>& bcd, uint8_t digits[19], size_t &dlen) {
  dlen = 0;
  for (size_t i = 0; i < bcd.size(); ++i) {
    uint8_t hi = (bcd[i] >> 4) & 0x0F;
    uint8_t lo = bcd[i] & 0x0F;
    if (hi <= 9) { if (dlen < 19) digits[dlen++] = hi; else return false; }
    else if (hi != 0x0F) return false;
    if (lo <= 9) { if (dlen < 19) digits[dlen++] = lo; else return false; }
    else if (lo == 0x0F) break;      // padding nibble indicates end
    else return false;
  }
  if (dlen < 8 || dlen > 19) return false;
  return true;
}

bool PN532::read_mifare_plus_bytes_(uint8_t start_page, uint16_t num_bytes, std::vector<uint8_t> &data) {
  std::vector<uint8_t> response;

  //=========================== read file (PPSE)
  std::vector<uint8_t> apdu = {
    0x00, 0xa4, 0x04, 0x00,
    0x0e,
    0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31,
    0x00
  };

  ESP_LOGD(TAG, "Sending request to read file");
  if (!sendAPDU(apdu, response)) return false;

  auto adf_name = findTag(response, nfc::EMV_TAG_AID);
  if (adf_name.empty()) {
    ESP_LOGW(TAG, "AID retrieval failed");
    return false;
  }
  ESP_LOGD(TAG, "Found ADF name: %s", format_hex_pretty(adf_name).c_str());

  //============================== select application
  apdu = {0x00, 0xa4, 0x04, 0x00};
  apdu.push_back(adf_name.size());
  apdu.insert(std::end(apdu), std::begin(adf_name), std::end(adf_name));
  apdu.push_back(0x00);

  ESP_LOGD(TAG, "Sending request to select application and get PDOL #1");
  if (!sendAPDU(apdu, response)) {
    ESP_LOGD(TAG, "Sending request to select application and get PDOL #2");
    if (!sendAPDU(apdu, response)) {
      ESP_LOGD(TAG, "Sending request to selct application and get PDOL #3");
      if (!sendAPDU(apdu, response)) {
        ESP_LOGD(TAG, "Failed request to selct application and get PDOL. Givinig up.");
        return false;
      }
    }
  }

  auto pdol = findTag(response, nfc::EMV_TAG_PDOL);
  ESP_LOGD(TAG, "Found PDOL: %s", format_hex_pretty(pdol).c_str());

  //=========================== GPO (AIP/AFL)
  apdu = {0x80, 0xa8, 0x00, 0x00};
  auto pdol_data = constructPdolData(pdol);
  apdu.push_back(pdol_data.size() + 2);
  apdu.push_back(nfc::EMV_TAG_COMMAND);
  apdu.push_back(pdol_data.size());
  apdu.insert(std::end(apdu), std::begin(pdol_data), std::end(pdol_data));
  apdu.push_back(0x00);

  ESP_LOGD(TAG, "Sending request for AFL");
  if (!sendAPDU(apdu, response)) {
    ESP_LOGD(TAG, "Sending request for AFL retry ");
    if (!sendAPDU(apdu, response)) {
      ESP_LOGD(TAG, "Sending request for AFL retry #2");
      if (!sendAPDU(apdu, response)) {
        ESP_LOGD(TAG, "Sending request for AFL failes 3 times. Giving up.");
        return false;
      }
    }
  }

  // ---- Case 1: Some cards return Track-2 (9F6B) in GPO response ------------
  {
    auto t2 = findTag(response, nfc::EMV_TAG_TRACK2);
    if (!t2.empty()) {
      ESP_LOGD(TAG, "Found TRACK2: %s", format_hex_pretty(t2).c_str());
      uint8_t digits[19]; size_t dlen = 0;
      if (pan_from_track2_nibbles_(t2, digits, dlen)) {        
        if (sha256_bytes_salted(digits, dlen, this->get_salt(), data)) {
          ESP_LOGD(TAG, "NDEF (PAN hash) size=%u", (unsigned)data.size());
          return true;
        }
      }
      // If parsing failed, continue to AFL reads below
    }
  }

  //=========================== READ RECORDS via AFL ---------------------------
  auto afl = findTag(response, 0x94);
  ESP_LOGD(TAG, "Found AFL: %s", format_hex_pretty(afl).c_str());
  if (afl.size() < 4 || (afl.size() % 4) != 0) {
    ESP_LOGW(TAG, "Invalid AFL found: %s", format_hex_pretty(afl).c_str());
    return false;
  }

  uint8_t pos = 0;
  while (pos + 3 < afl.size()) {
    uint8_t sfi_byte = afl[pos++];
    uint8_t start = afl[pos++];
    uint8_t end   = afl[pos++];
    (void)afl[pos++]; // auth_rec not needed here
    uint8_t sfi = (sfi_byte & 0b11111000) | 0b00000100;

    while (start <= end) {
      apdu = {0x00, 0xb2, start, sfi, 0x00};
      ESP_LOGD(TAG, "Sending SFI read request");
      if (sendAPDU(apdu, response)) {

        // ---- Try 9F6B (Track-2 equiv, BCD nibbles) -------------------------
        auto t2 = findTag(response, nfc::EMV_TAG_TRACK2);
        if (!t2.empty()) {
          uint8_t digits[19]; size_t dlen = 0;
          if (pan_from_track2_nibbles_(t2, digits, dlen)) {
            if (sha256_bytes_salted(digits, dlen, this->get_salt(), data)) {
              ESP_LOGD(TAG, "NDEF (PAN hash) size=%u", (unsigned)data.size());
              return true;
            }
          }
        }

        // ---- Try 56 (Track-1, ASCII) --------------------------------------
        auto t1 = findTag(response, nfc::EMV_TAG_TRACK1);
        if (!t1.empty()) {
          uint8_t digits[19]; size_t dlen = 0;
          if (pan_from_track1_ascii_(t1, digits, dlen)) {
            if (sha256_bytes_salted(digits, dlen, this->get_salt(), data)) {
              ESP_LOGD(TAG, "NDEF (PAN hash) size=%u", (unsigned)data.size());
              return true;
            }
          }
        }

        // ---- Try 5A (PAN, BCD) --------------------------------------------
        auto t5a = findTag(response, nfc::EMV_TAG_PAN);
        if (!t5a.empty()) {
          uint8_t digits[19]; size_t dlen = 0;
          if (pan_from_tag5a_bcd_(t5a, digits, dlen)) {         
            if (sha256_bytes_salted(digits, dlen, this->get_salt(), data)) {
              ESP_LOGD(TAG, "NDEF (PAN hash) size=%u", (unsigned)data.size());
              return true;
            }
          }
        }

      } else {
        ESP_LOGD(TAG, "Failed SFI read request");
      }
      start++;
      yield();
    }
  }

  ESP_LOGD(TAG, "----------------------------CARD READING FAILED !!!");
  return false;
}

/*

*/
bool PN532::sendAPDU(std::vector<uint8_t> &apdu, std::vector<uint8_t> &response) {
  // construct command
  std::vector<uint8_t> command({
      PN532_COMMAND_INDATAEXCHANGE,
      0x01  // nTag Working with single card only supported by the framework
  });
  command.insert(command.end(), apdu.begin(), apdu.end());

  if (!this->write_command_(command)) {
    ESP_LOGW(TAG, "write commande from sendAPDU failed");
    return false;
  }

  if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response) || response[0] != 0x00) {
    ESP_LOGW(TAG, "read response from sendAPDU failed");    
    return false;    
  }

  ESP_LOGD(TAG, "Data read: %s", format_hex(response).c_str());

  if (response[response.size() - 1] != 0x00 || response[response.size() - 2] != 0x90) {
    // full list of error codes https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
    ESP_LOGW(TAG, "APDU command returned error: %s", format_hex(&response.data()[response.size() - 2], 2).c_str());
    return false;
  }
  // remove technical bytes for easier further processing
  // first byte is 0x00
  // last two bytes response code
  response = {response.begin() + 1, response.end() - 2};
  return true;
}

/*
simplified for BER-TLV parsing
assumes data starts with tag
works only with 1 and 2 byte tags
works only with 255 bytes max length tag values.
puts everything into flat map, does not keep tag structure relations.
*/

void PN532::parseTags(std::vector<uint8_t> &ber_data, std::map<uint16_t, std::vector<uint8_t>> &tagMap) {
  // data must begin with tag
  uint8_t headerLen = 0;
  uint16_t tag = ber_data[headerLen++];

  if ((tag & 0x1F) == 0x1F)  // means we have multibyte tag
  {
    tag = (tag << 8) + ber_data[headerLen++];
  }

  uint16_t len = ber_data[headerLen++];
  if (ber_data.size() > len + headerLen) {
    // the tag does not cover full vector, remainder needs to be parsed recursivelly
    std::vector<uint8_t> remainingData = {ber_data.begin() + headerLen + len,
                                          ber_data.end()};  // skip tag and len bytes in begining
    parseTags(remainingData, tagMap);
  }

  // safety check before vector operation
  if (ber_data.size() >= len + headerLen) {
    std::vector<uint8_t> tagValue = {ber_data.begin() + headerLen, ber_data.begin() + headerLen + len};
    //tagMap.insert(std::pair<uint16_t, uint8_t *>(tag, tagValue.data()));
    tagMap.insert(std::make_pair(tag, std::vector<uint8_t>(tagValue.begin(), tagValue.end())));
    // if the tag is template tag, need to parse contents recursivelly
    if (tag == 0x6F || tag == 0xA5 || tag == 0xBF0C || tag == 0x61) {
      parseTags(tagValue, tagMap);
    }
  }
}

std::vector<uint8_t> PN532::constructPdolData(std::vector<uint8_t> &pdol) {
  if (pdol.size() < 2)  // we never shoudl get size() ==1, but just to catch some invalid cases
    return {};

  std::vector<uint8_t> result;
  while (pdol.size() > 1) {
    uint8_t headerLen = 0;
    uint16_t tag = pdol[headerLen++];

    if ((tag & 0x1F) == 0x1F)  // means we have multibyte tag
    {
      tag = (tag << 8) + pdol[headerLen++];
    }
    uint16_t len = pdol[headerLen++];
    std::vector<uint8_t> tagValue(0);

    switch (tag) {  // generate meaningful values for known tags
      case 0x9F66:  //	Terminal Transaction Qualifiers (TTQ)
/*        tagValue = {
            0x36, 0xA0, 0x40,
            0x00};  // https://mstcompany.net/blog/acquiring-emv-transaction-flow-part-4-pdol-and-contactless-cards-characteristic-features-of-qvsdc-and-quics
            */
            tagValue = {
            0xF0, 0x20, 0x40,
            0x00};  // https://stackoverflow.com/questions/55337693/generate-get-processing-options-gpo-for-emv-card-apdu-by-pdol
        break;
      case 0x9F02:  //	Amount, Authorised (Numeric)
      case 0x9F03:  // Amount, Other (Numeric)
        tagValue = {0x00, 0x00, 0x00, 0x00, 0x10, 0x00};
        break;
      case 0x9F1A:                // Terminal Country Code https://www.iban.com/country-codes
        tagValue = {0x02, 0x76};  // Germany
        break;
      case 0x5F2A:                // Transaction Currency Code https://www.iban.com/currency-codes
        tagValue = {0x09, 0x78};  // EUR
        break;
      case 0x9A:   // Transaction Date (YYMMDD)
        ESPTime time_ = ESPTime::from_epoch_local(::time(nullptr));
        tag_value.push_back(static_cast<uint8_t>((now.year - 2000) & 0xFF));
        tag_value.push_back(static_cast<uint8_t>(now.month));
        tag_value.push_back(static_cast<uint8_t>(now.day_of_month));      
      /*  tagValue = {
            0x23,
            0x11,
            0x25,
        };*/
        break;

      case 0x9F37:  // Unpredictable Number (UN)
        tagValue = {0xB5, 0x43, 0xFF, 0x89};
        break;
      default:  // generate zeroes
        tagValue.resize(len, 0);
    }
    result.insert(result.end(), tagValue.begin(), tagValue.end());
    pdol.erase(pdol.begin(), pdol.begin() + headerLen);
  }
  return result;
}

std::vector<uint8_t> PN532::findTag(std::vector<uint8_t> &ber_data, uint16_t tagToFind) {
  // ber must have at least 3 bytes - tag, length and value
  if (ber_data.size() < 3)
    return {};

  // data must begin with tag
  uint8_t headerLen = 0;
  uint16_t tag = ber_data[headerLen++];

  if ((tag & 0x1F) == 0x1F)  // means we have multibyte tag
  {
    tag = (tag << 8) + ber_data[headerLen++];
  }
  //uint8_t len = ber_data[headerLen++];
  //if(len & 0b10000000) //if bit 8 is set, lenghts should be read from next byte
  //  len = ber_data[headerLen++];
  //read leangth
  uint8_t len_byte = ber_data[headerLen++];
  size_t len = 0;
  if (len_byte & 0x80) {
    uint8_t count = len_byte & 0x7F;
    while (count-- && headerLen < ber_data.size()) {
      len = (len << 8) | ber_data[headerLen++];
    }
  } else {
    len = len_byte;
  }
  // safety check before vector operation
  if (ber_data.size() >= len + headerLen) {
    std::vector<uint8_t> tagValue = {ber_data.begin() + headerLen, ber_data.begin() + headerLen + len};
    if (tag == tagToFind)
      return tagValue;
    // if the tag is template tag, need to parse contents recursivelly
    if (tag == 0x6F || tag == 0xA5 || tag == 0xBF0C || tag == 0x61 || tag == 0x77 || tag == 0x70) {
      tagValue = findTag(tagValue, tagToFind);
      if (!tagValue.empty()) {
        return tagValue;
      }
    }
  }

  // the tag does not cover full vector, remainder needs to be parsed recursivelly
  if (ber_data.size() > len + headerLen) {
    std::vector<uint8_t> remainingData = {ber_data.begin() + headerLen + len,
                                          ber_data.end()};  // skip tag and len bytes in begining
    std::vector<uint8_t> tagValue = findTag(remainingData, tagToFind);
    if (!tagValue.empty()) {
      return tagValue;
    }
  }
  return {};
}

}  // namespace pn532
}  // namespace esphome
