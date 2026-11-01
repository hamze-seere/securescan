import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp, parseTargetUrl, BlockedTargetError } from "../src/lib/scanner/ssrf";

test("blocks private, loopback, link-local and reserved IPv4", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255"]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test("allows public IPv4", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "93.184.216.34"]) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

test("blocks private and tricky IPv6 forms", () => {
  for (const ip of ["::1", "::", "fe80::1", "fd00::1", "fc00::abcd", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "ff02::1"]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test("allows public IPv6", () => {
  for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888"]) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

test("parseTargetUrl adds https:// and accepts normal sites", () => {
  assert.equal(parseTargetUrl("example.com").toString(), "https://example.com/");
  assert.equal(parseTargetUrl("http://example.com/path#frag").toString(), "http://example.com/path");
});

test("parseTargetUrl rejects dangerous inputs", () => {
  const bad = [
    "file:///etc/passwd",
    "ftp://example.com",
    "gopher://example.com",
    "http://localhost",
    "http://api.localhost",
    "http://127.0.0.1",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://user:pass@example.com",
    "http://example.com:6379",
    "http://intranet",
    "",
  ];
  for (const input of bad) {
    assert.throws(() => parseTargetUrl(input), BlockedTargetError, input);
  }
});

test("decimal / hex IP encodings are normalised by the URL parser and blocked", () => {
  // new URL() turns these into 127.0.0.1, so they hit the IP check.
  for (const input of ["http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/"]) {
    assert.throws(() => parseTargetUrl(input), BlockedTargetError, input);
  }
});

test("blocks the less common reserved IPv6 ranges", () => {
  for (const ip of ["fec0::1", "100::1", "64:ff9b:1::a00:1", "2001::1", "2001:10::1", "2001:db8::1"]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test("a trailing root dot does not get around the hostname rules", () => {
  for (const input of ["http://localhost./", "http://localhost../", "http://metadata.google.internal./", "http://printer.local./"]) {
    assert.throws(() => parseTargetUrl(input), BlockedTargetError, input);
  }
});
