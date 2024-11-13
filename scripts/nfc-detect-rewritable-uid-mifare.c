/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/** @file This is a test that detects chinese backdoored Mifare cards with rewritable UID and backdoored
 * read/write on sectors.
 *
 * Adapted from nfc-anticol.c from libnfc examples.
 */

/**
 * @file nfc-anticol.c
 * @brief Generates one ISO14443-A anti-collision process "by-hand"
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>

#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264

extern void warnx (const char *__format, ...)
     __attribute__ ((__format__ (__printf__, 1, 2)));

/**
 * @macro ERR
 * @brief Print a error message
 */
#ifdef DEBUG
#  define ERR(...) do { \
    warnx ("ERROR %s:%d", __FILE__, __LINE__); \
    warnx ("    " __VA_ARGS__ ); \
  } while (0)
#else
#  define ERR(...)  warnx ("ERROR: " __VA_ARGS__ )
#endif

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static size_t szRx = sizeof(abtRx);
static uint8_t abtAtqa[2];
static nfc_device *pnd;

bool    quiet_output = false;
bool    force_rats = false;
bool    timed = false;
bool    iso_ats_supported = false;

// ISO14443A Anti-Collision Commands
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  strangeWupa[1] = { 0x40 };
uint8_t  chineseBackdoorTest[1] = { 0x43 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };
#define CASCADE_BIT 0x04

void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
    size_t  szPos;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}

void
print_hex_bits(const uint8_t *pbtData, const size_t szBits)
{
    uint8_t uRemainder;
    size_t  szPos;
    size_t  szBytes = szBits / 8;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }

    uRemainder = szBits % 8;
    // Print the rest bits
    if (uRemainder != 0) {
        if (uRemainder < 5)
            printf("%01x (%d bits)", pbtData[szBytes], uRemainder);
        else
            printf("%02x (%d bits)", pbtData[szBytes], uRemainder);
    }
    printf("\n");
}

static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex_bits(pbtTx, szTxBits);
  }
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if (timed) {
    if ((szRxBits = nfc_initiator_transceive_bits_timed(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL, &cycles)) < 0)
      return false;
    if ((!quiet_output) && (szRxBits > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
      return false;
  }
  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex_bits(abtRx, szRxBits);
  }
  // Succesful transfer
  return true;
}


static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex(pbtTx, szTx);
  }
  int res;
  // Transmit the command bytes
  if (timed) {
    if ((res = nfc_initiator_transceive_bytes_timed(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), &cycles)) < 0)
      return false;
    if ((!quiet_output) && (res > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
      return false;
  }
  szRx = res;
  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex(abtRx, szRx);
  }
  // Succesful transfer
  return true;
}

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\tHelp. Print this message.\n");
  printf("\t-q\tQuiet mode. Suppress output of READER and EMULATOR data (improves timing).\n");
  printf("\t-f\tForce RATS.\n");
  printf("\t-t\tMeasure response time (in cycles).\n");
}

int
main(int argc, char *argv[])
{
  int     arg;

  // Get commandline options
  for (arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "-h")) {
      print_usage(argv);
      exit(EXIT_SUCCESS);
    } else if (0 == strcmp(argv[arg], "-q")) {
      quiet_output = true;
    } else if (0 == strcmp(argv[arg], "-f")) {
      force_rats = true;
    } else if (0 == strcmp(argv[arg], "-t")) {
      timed = true;
    } else {
      ERR("%s is not supported option.", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
    }
  }

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Disable 14443-4 autoswitching
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n\n", nfc_device_get_name(pnd));

  // Send the 7 bits of "Chinese wakeup"
  if (!transmit_bits(strangeWupa, 7)) {
    printf("This is NOT a backdoored rewritable UID chinese card\n");
    exit(EXIT_SUCCESS);
  }
  memcpy(abtAtqa, abtRx, 2);

  // Strange backdoored command that is not implemented in normal Mifare
  bool success = transmit_bytes(chineseBackdoorTest, 1);
  if (success) {
    printf("This is backdoored rewritable UID chinese card\n");
  } else {
    printf("This is NOT a backdoored rewritable UID chinese card\n");
  }


  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
