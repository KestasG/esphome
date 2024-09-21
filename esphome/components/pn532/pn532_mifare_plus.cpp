#include <memory>

#include "pn532.h"
#include "esphome/core/log.h"

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

bool PN532::read_mifare_plus_bytes_(uint8_t start_page, uint16_t num_bytes, std::vector<uint8_t> &data) {
  std::vector<uint8_t> response;

  //=========================== read file

  // skip proper EMV protocols try reading known file  
  std::vector<uint8_t> apdu = {
    0x00, 0xa4, 0x04, 0x00, //APDU SELECT CLA,INS,P1,P2
    0x0e, // Lc command data length
    0x32, 0x50, 0x41, 0x59, 0x2e,0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, // commanda data - 2pay.sys.ddf01
    0x00 // Le
  };

  ESP_LOGD(TAG, "Sending request to read file");
  if (!sendAPDU(apdu, response)) {
    return false;  //
  }
  // the response should contain tag 4F with AID required for next step
  auto adf_name = findTag(response, nfc::EMV_TAG_AID);

  if (adf_name.empty()) {
    ESP_LOGW(TAG, "AID retrieval failed");
    return false;
  }
  ESP_LOGD(TAG, "Found ADF name: %s", format_hex_pretty(adf_name).c_str());

  //============================== select application
  // select application
  // AID 	A0 00 00 00 04 10 10 - Mastercard
  // apdu = {0x00, 0xa4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};
  apdu = {0x00, 0xa4, 0x04, 0x00};  //APDU SELECT CLA,INS,P1,P2

  // add the AID from previous response
  apdu.push_back(adf_name.size());
  apdu.insert(std::end(apdu), std::begin(adf_name), std::end(adf_name));
  //unsure if Lc byte 0x00 is needed at the end
  apdu.push_back(0x00);

  ESP_LOGD(TAG, "Sending request to select application and get PDOL #1");
  if (!sendAPDU(apdu, response)) {
    ESP_LOGD(TAG, "Sending request to select application and get PDOL #2");
    if (!sendAPDU(apdu, response)) {
      ESP_LOGD(TAG, "Sending request to selct application and get PDOL #3");
      if (!sendAPDU(apdu, response)) {
        ESP_LOGD(TAG, "Failed request to selct application and get PDOL. Givinig up.");
        return false;  //
      }
    }
  }

  // looking for PDOL
  auto pdol = findTag(response, nfc::EMV_TAG_PDOL);
  // pdol can be empty
  ESP_LOGD(TAG, "Found PDOL: %s", format_hex_pretty(pdol).c_str());

  //=========================== read AFL

  // construct request from PDOL tags

  
  

  apdu = {0x80, 0xa8, 0x00, 0x00}; //APDU GPO CLA,INS,P1,P2

  auto pdol_data = constructPdolData(pdol);
  apdu.push_back(pdol_data.size() + 2);  // data len plus tag byte plus len byte
  apdu.push_back(nfc::EMV_TAG_COMMAND);       // the tag
  apdu.push_back(pdol_data.size());      // data len
  apdu.insert(std::end(apdu), std::begin(pdol_data), std::end(pdol_data)); //data
  apdu.push_back(0x00);                   // Le
  /*  
  Empty PDOL example
  80 a8 00 00 02 83 00 00
  VISA Example
  0x23, //length
  0x83, //tag
  0x21,//length
  0x36, 0xA0, 0x40, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x08, 0x40,
  0x00, 0x00, 0x00, 0x00, 0x00,
  0x09, 0x78,
  0x23, 0x11, 0x25,
  0x00,
  0x00, 0x10, 0x20, 0x30};
  */
  ESP_LOGD(TAG, "Sending request for AFL");
  if (!sendAPDU(apdu, response)) {
    ESP_LOGD(TAG, "Sending request for AFL retry ");
    if (!sendAPDU(apdu, response)) {
      ESP_LOGD(TAG, "Sending request for AFL retry #2");
      if (!sendAPDU(apdu, response)) {
        ESP_LOGD(TAG, "Sending request for AFL failes 3 times. Giving up.");
        return false;  //
      }
    }
  }

  // some cards (at least Revolut VISA) returns Track 2 data here, so PAN can be retrieved)
  auto track2 = findTag(response, nfc::EMV_TAG_TRACK2);  
  ESP_LOGD(TAG, "Found TRACK2: %s", format_hex_pretty(track2).c_str());
  if (track2.size() > 0) {
    parse_track2(track2);
    return false;
  }

  //=========================== read SFI

  auto afl = findTag(response, 0x94);  // AFL records
  ESP_LOGD(TAG, "Found AFL: %s", format_hex_pretty(afl).c_str());
  if (afl.size() < 4 || (afl.size() % 4) != 0) {
    ESP_LOGW(TAG, "Invalid AFL found: %s", format_hex_pretty(afl).c_str());
    return false;
  }

  // for each SFI
  uint8_t pos = 0;
  while (pos < afl.size() - 4) {  // ensure there are at least 4 bytes to read
    uint8_t sfi = (afl[pos++] & 0b11111000) |
                  0b00000100;  // SFI is taken from high 5 bits and 0b100 added meaning we want to read all records
    uint8_t start = afl[pos++];
    uint8_t end = afl[pos++];
    uint8_t auth_rec = afl[pos++];
    // for each records inside SFI
    while (start <= end) {
      apdu = {0x00, 0xb2};  // apdu READ RECORD
      apdu.push_back(start);
      apdu.push_back(sfi);
      apdu.push_back(0x00);
      ESP_LOGD(TAG, "Sending SFI read request");
      if (sendAPDU(apdu, response)) {
        auto pan = findTag(response, nfc::EMV_TAG_TRACK2);  // TRACK 2
        yield();
        if (pan.size() > 0) {
          pan = parse_track2(pan);
          return false;
        } else {
          pan = findTag(response, nfc::EMV_TAG_TRACK1);  // TRACK 1
          yield();
          if (pan.size() > 0) {
            pan = parse_track1(pan);
            return false;
          } else {
            pan = findTag(response, nfc::EMV_TAG_PAN);  // TRACK 1
            yield();
            if (pan.size() > 0) {
              pan = parse_pan(pan);
              return false;
            }
          }
        }
      } else {
        ESP_LOGD(TAG, "Failed SFI read request");
      }
      start++;
    }
  }

  // visa revolut infinite
  // SFI 03  start 07, end 07
  //apdu = {0x00, 0xb2, 0x07, 0x1C, 0x00};

  // 00 b2 01 0c 00
  // apdu ={PN532_COMMAND_INDATAEXCHANGE, 0x01, 0x00, 0xb2, 0x01, 0x14, 0x00}; working for garmin pay
  // apdu = {0x00, 0xb2, 0x01, 0x14, 0x00};
  /*ESP_LOGD(TAG, "Sending request to read SFI");
  if (!sendAPDU(apdu, response)) {
    return false;  //
  }*/

  // fnv1_hash

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

void PN532::parseTags(std::vector<uint8_t> &ber_data, std::map<uint16_t, uint8_t *> &tagMap) {
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
    tagMap.insert(std::pair<uint16_t, uint8_t *>(tag, tagValue.data()));
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
      case 0x9A: {  // Transaction Date (YYMMDD)
        ESPTime time_ = ESPTime::from_epoch_local(::time(nullptr));
        //  tagValue.push_back(time_.year-2000);
        //  tagValue.push_back(time_.month);
        //  tagValue.push_back(time_.day_of_month);
      }
        tagValue = {
            0x23,
            0x11,
            0x25,
        };
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
  uint8_t len = ber_data[headerLen++];
  if(len & 0b10000000) //if bit 8 is set, lenghts should be read from next byte
    len = ber_data[headerLen++];
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
