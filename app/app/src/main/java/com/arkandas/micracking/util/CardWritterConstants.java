package com.arkandas.micracking.util;

/**
 * Constant values for writing the Mifare Classic clone card
 */
public class CardWritterConstants {

    // Default Sector Key
    public static final String SectorKeyDefault = "FFFFFFFFFFFF";
    // Key A
    public static final String SectorKeyA = "FFFFFFFFFFFF";
    // Key B
    public static final String SectorKeyB = "FFFFFFFFFFFF";

    // Constants for the Block Checker

    // --------- Sector 0 ---------
    // Global Block 1 -> Sector 0 Block 0
    public static final String Sector0Block0 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    // --------- Sector 09 ---------
    // Global Block 36 -> Sector 9 Block 0
    public static final String Sector9Block0 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    // Global Block 37 -> Sector 9 Block 1
    public static final String Sector9Block1 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    // Global Block 38 -> Sector 9 Block 2
    public static final String Sector9Block2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    // --------- Sector 10 ---------
    // Global Block 40 -> Sector 10 Block 0
    public static final String Sector10Block0 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    // Global Block 41 -> Sector 10 Block 1
    public static final String Sector10Block1 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    // Global Block 42 -> Sector 10 Block 2
    public static final String Sector10Block2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    // --------- Sector 11 ---------
    // Global Block 44 -> Sector 11 Block 0
    public static final String Sector11Block0 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
}
