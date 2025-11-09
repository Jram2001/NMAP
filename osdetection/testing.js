function calculateIPChecksum(buffer, headerLength) {
    let sum = 0;

    // Sum all 16-bit words, skipping checksum field (bytes 10-11)
    for (let i = 0; i < headerLength; i += 2) {
        if (i === 10) continue; // Skip checksum field

        const word = (buffer[i] << 8) + buffer[i + 1];
        sum += word;
    }

    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return (~sum) & 0xFFFF;
}

function validateIPPacket(buffer) {
    const results = {
        valid: true,
        errors: [],
        warnings: [],
        details: {}
    };

    // Check minimum length
    if (buffer.length < 20) {
        results.valid = false;
        results.errors.push(`Packet too short: ${buffer.length} bytes (minimum 20)`);
        return results;
    }

    // Parse IP header
    const version = (buffer[0] >> 4) & 0x0F;
    const ihl = buffer[0] & 0x0F;
    const headerLength = ihl * 4;
    const totalLength = (buffer[1] << 8) | buffer[2];
    const ttl = buffer[8];
    const protocol = buffer[9];
    const checksumInPacket = (buffer[10] << 8) | buffer[11];
    const srcIp = `${buffer[12]}.${buffer[13]}.${buffer[14]}.${buffer[15]}`;
    const destIp = `${buffer[16]}.${buffer[17]}.${buffer[18]}.${buffer[19]}`;

    results.details = {
        version,
        ihl,
        headerLength,
        totalLength,
        ttl,
        protocol: protocol === 6 ? 'TCP' : protocol === 17 ? 'UDP' : protocol === 1 ? 'ICMP' : protocol,
        checksumInPacket: `0x${checksumInPacket.toString(16).padStart(4, '0')}`,
        srcIp,
        destIp
    };

    // Validate version
    if (version !== 4) {
        results.valid = false;
        results.errors.push(`Invalid IP version: ${version} (expected 4)`);
    }

    // Validate IHL
    if (ihl < 5) {
        results.valid = false;
        results.errors.push(`Invalid IHL: ${ihl} (minimum 5)`);
    }

    if (headerLength > buffer.length) {
        results.valid = false;
        results.errors.push(`Header length (${headerLength}) exceeds packet length (${buffer.length})`);
    }

    // Validate total length
    if (totalLength < headerLength) {
        results.valid = false;
        results.errors.push(`Total length (${totalLength}) less than header length (${headerLength})`);
    }

    if (totalLength !== buffer.length) {
        results.warnings.push(`Total length field (${totalLength}) doesn't match buffer length (${buffer.length})`);
    }

    // Validate TTL
    if (ttl === 0) {
        results.warnings.push('TTL is 0 (packet should be dropped)');
    }

    // Calculate and validate checksum
    const calculatedChecksum = calculateIPChecksum(buffer, headerLength);
    results.details.calculatedChecksum = `0x${calculatedChecksum.toString(16).padStart(4, '0')}`;
    results.details.checksumMatch = calculatedChecksum === checksumInPacket;

    if (calculatedChecksum !== checksumInPacket) {
        results.valid = false;
        results.errors.push(`Checksum mismatch! Expected: 0x${calculatedChecksum.toString(16).padStart(4, '0')}, Found: 0x${checksumInPacket.toString(16).padStart(4, '0')}`);
    }

    // Validate source/dest IPs
    if (srcIp === '0.0.0.0') {
        results.warnings.push('Source IP is 0.0.0.0');
    }

    if (destIp === '0.0.0.0') {
        results.warnings.push('Destination IP is 0.0.0.0');
    }

    return results;
}

// Test with your probes
const probes = [
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0x15, 0x74, 0x60, 0x00, 0x40, 0x06, 0x78, 0xb6, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0xff, 0xff, 0xf2, 0xd0, 0x00, 0x00]),
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0xd2, 0x1c, 0x60, 0x00, 0x40, 0x06, 0xbc, 0x0d, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x2b, 0xff, 0xff, 0xf2, 0xa5, 0x00, 0x00]),
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0xc3, 0xc1, 0x60, 0x00, 0x40, 0x06, 0xca, 0x68, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0xff, 0xff, 0xf2, 0xc0, 0x00, 0x00]),
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0x6a, 0x14, 0x60, 0x00, 0x40, 0x06, 0x24, 0x16, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0xf2, 0xce, 0x00, 0x00]),
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0x5e, 0x9f, 0x60, 0x00, 0x40, 0x06, 0x2f, 0x8b, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0xff, 0xff, 0xf2, 0xc0, 0x00, 0x00]),
    Buffer.from([0x45, 0x00, 0x00, 0x28, 0x3a, 0x29, 0x60, 0x00, 0x40, 0x06, 0x54, 0x01, 0x0a, 0xe0, 0x3b, 0xe0, 0x0a, 0xe0, 0x3b, 0x06, 0x30, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x29, 0xff, 0xff, 0xf2, 0xa7, 0x00, 0x00])
];

console.log('='.repeat(80));
console.log('IP PACKET VALIDATION REPORT');
console.log('='.repeat(80));

probes.forEach((probe, index) => {
    console.log(`\n📦 Probe #${index + 1}:`);
    const validation = validateIPPacket(probe);

    console.log('\n  Details:');
    Object.entries(validation.details).forEach(([key, value]) => {
        console.log(`    ${key}: ${value}`);
    });

    if (validation.errors.length > 0) {
        console.log('\n  ❌ Errors:');
        validation.errors.forEach(err => console.log(`    - ${err}`));
    }

    if (validation.warnings.length > 0) {
        console.log('\n  ⚠️  Warnings:');
        validation.warnings.forEach(warn => console.log(`    - ${warn}`));
    }

    if (validation.valid && validation.warnings.length === 0) {
        console.log('\n  ✅ VALID - All checks passed!');
    } else if (validation.valid) {
        console.log('\n  ✅ VALID - but has warnings');
    } else {
        console.log('\n  ❌ INVALID');
    }

    console.log('\n' + '-'.repeat(80));
});

console.log('\n' + '='.repeat(80));