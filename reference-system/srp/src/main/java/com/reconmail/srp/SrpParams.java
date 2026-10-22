package com.reconmail.srp;

import java.math.BigInteger;

/**
 * The SRP group: a safe-prime modulus {@code N} and generator {@code g}.
 * See {@code docs/dossier/02-authentication-srp.md}.
 *
 * <p>Proton serves {@code N} as an OpenPGP-signed blob that the client must
 * verify before use. Here we ship the standard RFC 5054 2048-bit group as the
 * default; the auth server would sign and serve its own modulus the same way.</p>
 */
public record SrpParams(BigInteger N, BigInteger g) {

    /** RFC 5054, Appendix A — the 2048-bit group, with g = 2. */
    public static SrpParams default2048() {
        String hex =
                "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
                "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
                "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
                "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
                "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
                "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
                "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
                "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
                "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
                "9E4AFF73";
        return new SrpParams(new BigInteger(hex, 16), BigInteger.valueOf(2));
    }
}
