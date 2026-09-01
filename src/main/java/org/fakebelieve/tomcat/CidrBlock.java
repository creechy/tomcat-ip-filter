package org.fakebelieve.tomcat;

import java.math.BigInteger;
import java.net.InetAddress;

/**
 * Represents an IP address or CIDR block (both IPv4 and IPv6) and provides
 * efficient matching for IP addresses against the block.
 */
public class CidrBlock {
    private final InetAddress address;
    private final int prefixLength;
    private final BigInteger networkValue;
    private final BigInteger netmask;
    private final int bitLength;

    public CidrBlock(String cidrNotation) {
        String trimmed = cidrNotation.trim();
        int slashIdx = trimmed.indexOf('/');
        String ipPart;
        int prefix;

        try {
            if (slashIdx != -1) {
                ipPart = trimmed.substring(0, slashIdx).trim();
                prefix = Integer.parseInt(trimmed.substring(slashIdx + 1).trim());
            } else {
                ipPart = trimmed;
                InetAddress tempAddr = InetAddress.getByName(ipPart);
                prefix = (tempAddr.getAddress().length * 8);
            }

            this.address = InetAddress.getByName(ipPart);
            byte[] addrBytes = this.address.getAddress();
            this.bitLength = addrBytes.length * 8;

            if (prefix < 0 || prefix > this.bitLength) {
                throw new IllegalArgumentException("Invalid prefix length " + prefix + " for " + bitLength + "-bit address.");
            }
            this.prefixLength = prefix;

            BigInteger addrInt = new BigInteger(1, addrBytes);
            if (this.prefixLength == 0) {
                this.netmask = BigInteger.ZERO;
            } else {
                this.netmask = BigInteger.ONE.shiftLeft(this.prefixLength)
                        .subtract(BigInteger.ONE)
                        .shiftLeft(this.bitLength - this.prefixLength);
            }
            this.networkValue = addrInt.and(this.netmask);

        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CIDR notation: " + cidrNotation, e);
        }
    }

    public boolean matches(String ipStr) {
        try {
            InetAddress targetAddr = InetAddress.getByName(ipStr);
            byte[] targetBytes = targetAddr.getAddress();
            if (targetBytes.length * 8 != this.bitLength) {
                return false; // Different IP versions (IPv4 vs IPv6)
            }
            BigInteger targetInt = new BigInteger(1, targetBytes);
            BigInteger targetNetwork = targetInt.and(this.netmask);
            return targetNetwork.equals(this.networkValue);
        } catch (Exception e) {
            return false;
        }
    }

    public InetAddress getAddress() {
        return address;
    }

    public int getPrefixLength() {
        return prefixLength;
    }
}
