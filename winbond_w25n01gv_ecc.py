#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  Winbond W25N01GV ECC Algorithm

  Error Correction Code implementation for Winbond W25N01GV Serial NAND flash chip.
  Based on reverse engineering by Troed Sångberg (https://codeberg.org/troed/winbond_ecc)

  The Winbond W25N01GV uses a Hamming code-based ECC algorithm with parity correction.
  
  - Main Sector ECC: 6 bytes for each 512-byte sector (3 bytes per 256-byte sub-sector)
  - Spare Area ECC: 2 bytes for 10 bytes of spare data (User Data I + Sector ECC)

  Licensed as Creative Commons Zero 1.0 Universal
  https://creativecommons.org/publicdomain/zero/1.0/
"""

__version__ = '0.1'
__author__ = 'troed'


def winbond_compute_subsector_ecc(sub):
    """Compute 3-byte ECC for a 256-byte sub-sector.
    
    Algorithm based on Hamming code with parity correction:
    1. Compute Hamming syndrome by XORing all bit positions where 1 bits occur
    2. Count total number of 1 bits
    3. Compute parity (0xff if odd, 0x00 if even)
    4. Compute ECC bytes from syndrome and parity
    
    Args:
        sub: 256 bytes of data
        
    Returns:
        tuple: (byte0, byte1, byte2) - 3 bytes of ECC
    """
    # Step 1: Compute Hamming syndrome
    # The syndrome is the XOR of all bit positions (byte_pos * 8 + bit_pos)
    # where a 1 bit occurs
    syn = 0
    for byte_pos in range(256):
        bv = sub[byte_pos]
        for i in range(8):
            if bv & (1 << i):
                syn ^= (byte_pos * 8 + i)
    
    # Step 2: Count total bits
    total_bits = sum(bin(b).count('1') for b in sub)
    
    # Step 3: Parity correction
    parity = 0xff if total_bits % 2 == 1 else 0
    
    # Step 4: Compute ECC byte 0
    # Lower 8 bits of syndrome XORed with parity
    byte0 = (syn & 0xff) ^ parity
    
    # Step 5: Compute ECC byte 1 and byte 2
    syn08 = syn & 0xff          # Lower 8 bits of syndrome
    syn811 = (syn >> 8) & 0x07  # Upper 3 bits of syndrome (bits 8-10)
    
    # Compute intermediate value g
    g = ((syn08 & 0x0f) << 12) | (syn811 << 4) | (syn08 >> 4)
    
    # Apply total_bits parity correction to g
    extra_13 = g ^ ((total_bits & 1) << 11)
    
    # Byte 1: combine upper bits of extra_13 with XOR of syn811 and parity mask
    b1_high = extra_13 >> 8
    b1_low = syn811 ^ (0x07 if total_bits % 2 == 1 else 0)
    byte1 = b1_high | b1_low
    
    # Byte 2: lower 8 bits of intermediate value
    byte2 = extra_13 & 0xff
    
    return byte0, byte1, byte2


def winbond_compute_sector_ecc(sector_data):
    """Compute 6-byte ECC for a 512-byte sector.
    
    A 512-byte sector is divided into two 256-byte sub-sectors.
    Each sub-sector gets 3 bytes of ECC.
    
    Args:
        sector_data: 512 bytes of data
        
    Returns:
        bytes: 6 bytes of ECC (3 bytes for each sub-sector)
    """
    sub1 = sector_data[0:256]
    sub2 = sector_data[256:512]
    
    b0_1, b1_1, b2_1 = winbond_compute_subsector_ecc(sub1)
    b0_2, b1_2, b2_2 = winbond_compute_subsector_ecc(sub2)
    
    return bytes([b0_1, b1_1, b2_1, b0_2, b1_2, b2_2])


def winbond_compute_spare_ecc(input_bytes):
    """Compute 2-byte Spare ECC from 10 input bytes.
    
    The Spare ECC protects bytes 4-13 of the spare area (User Data I + Sector ECC).
    Both output bytes are identical for redundancy.
    
    Args:
        input_bytes: 10 bytes from spare[4:14] = User Data I (4 bytes) + Sector ECC (6 bytes)
        
    Returns:
        bytes: 2 bytes where both bytes are identical (spare[14:16])
    """
    # Step 1: Compute Hamming syndrome over 10 input bytes
    syn = 0
    for byte_pos in range(10):
        bv = input_bytes[byte_pos]
        for i in range(8):
            if bv & (1 << i):
                syn ^= (byte_pos * 8 + i)
    
    # Step 2: Count total bits
    total_bits = sum(bin(b).count('1') for b in input_bytes)
    
    # Step 3: Compute parity
    parity = 0xff if total_bits % 2 == 1 else 0
    
    # Step 4: Compute ECC byte
    ecc_byte = (syn & 0xff) ^ parity
    
    # Step 5: Return both bytes (identical for redundancy)
    return bytes([ecc_byte, ecc_byte])


def winbond_compute_page_ecc(page_data, sectors_per_page=4):
    """Compute all ECC bytes for a complete page.
    
    The Winbond W25N01GV has 2112-byte pages with:
    - 2048 bytes of main data (4 x 512-byte sectors)
    - 64 bytes of spare area (4 x 16-byte spare areas)
    
    Args:
        page_data: 2048 bytes of main sector data
        sectors_per_page: Number of sectors per page (default: 4)
        
    Returns:
        dict: Dictionary containing 'sector_ecc' and 'spare_ecc' lists
    """
    sector_ecc = []
    spare_ecc = []
    
    # Compute Sector ECC for each sector
    sector_size = 512
    for i in range(sectors_per_page):
        sector = page_data[i * sector_size:(i + 1) * sector_size]
        ecc = winbond_compute_sector_ecc(sector)
        sector_ecc.append(ecc)
    
    return {'sector_ecc': sector_ecc}


def winbond_extract_spare_ecc(spare_data):
    """Extract Spare ECC from spare area data.
    
    Args:
        spare_data: 64 bytes of spare area data (for 4 sectors)
        
    Returns:
        list: List of 2-byte ECC values for each spare area
    """
    spare_ecc = []
    spare_size = len(spare_data)
    
    # Each spare area is 16 bytes, with Spare ECC at offset 14-15
    for i in range(0, spare_size, 16):
        if i + 16 <= spare_size:
            spare_area = spare_data[i:i + 16]
            ecc = spare_area[14:16]
            spare_ecc.append(ecc)
    
    return spare_ecc


def winbond_verify_and_correct_sector(sector_data, expected_ecc):
    """Verify sector data against expected ECC and attempt correction.
    
    The Winbond ECC algorithm provides:
    - 1-bit error correction
    - 2-bit error detection
    
    Args:
        sector_data: 512 bytes of sector data
        expected_ecc: 6 bytes of expected ECC
        
    Returns:
        tuple: (status, corrected_data, error_info)
            status: 0 = no errors, 1 = corrected, 2 = detected but uncorrectable, -1 = unknown
            corrected_data: corrected sector data (if correction was attempted)
            error_info: dict with error details (bit position, etc.)
    """
    # Compute actual ECC for the sector data
    actual_ecc = winbond_compute_sector_ecc(sector_data)
    
    # Compare ECC bytes
    ecc_diff = bytes(a ^ b for a, b in zip(actual_ecc, expected_ecc))
    
    # Count differing bytes
    diff_count = sum(1 for b in ecc_diff if b != 0)
    
    if diff_count == 0:
        # ECC matches - no errors detected
        return (0, sector_data, {'error_bits': 0})
    
    # For now, we can only detect errors but not correct them
    # The full correction algorithm would need to decode the Hamming code
    # and locate the error position from the syndrome
    
    # Check if it's a single-bit error in data (ECC difference pattern)
    # This is a simplified check - full correction would require more work
    if diff_count <= 3:  # ECC is 6 bytes, might be correctable
        return (2, sector_data, {'error_bits': diff_count, 'message': 'Error detected but correction not implemented'})
    
    return (-1, sector_data, {'error_bits': diff_count, 'message': 'Multiple errors detected'})
