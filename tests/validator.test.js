const test = require('node:test');
const assert = require('node:assert/strict');
const { isIP, normalizeInput, extractTld } = require('../src/utils/validator');
const { escapeMdV2 } = require('../src/utils/telegram');

test('isIP correctly distinguishes valid IPv4, IPv6 and invalid inputs', () => {
    assert.equal(isIP('8.8.8.8'), 4);
    assert.equal(isIP('1.1.1.1'), 4);
    assert.equal(isIP('2606:4700:4700::1111'), 6);
    assert.equal(isIP('2001:4860:4860::8888'), 6);

    assert.equal(isIP('999.999.999.999'), false);
    assert.equal(isIP('hello::world'), false);
    assert.equal(isIP('example.com'), false);
    assert.equal(isIP(''), false);
});

test('normalizeInput strips scheme, trailing slashes, and ports', () => {
    assert.equal(normalizeInput('https://google.com/'), 'google.com');
    assert.equal(normalizeInput('http://test.id/path/to/page'), 'test.id');
    assert.equal(normalizeInput('example.com:8080'), 'example.com');
    assert.equal(normalizeInput('  Pandi.ID. '), 'pandi.id');
});

test('extractTld extracts single and multi-level TLDs', () => {
    assert.equal(extractTld('example.com'), 'com');
    assert.equal(extractTld('pandi.id'), 'id');
    assert.equal(extractTld('web.id'), 'id');
    assert.equal(extractTld('domain.co.id'), 'co.id');
    assert.equal(extractTld('test.co.uk'), 'co.uk');
});

test('escapeMdV2 escapes special MarkdownV2 characters', () => {
    const raw = 'Hello_World *bold* [link]';
    const escaped = escapeMdV2(raw);
    assert.match(escaped, /\\_/);
    assert.match(escaped, /\\\*/);
    assert.match(escaped, /\\\[/);
    assert.match(escaped, /\\\]/);
});
