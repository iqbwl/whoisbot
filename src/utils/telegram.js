const escapeMdV2 = (s) => {
    return String(s).replace(/([_*[\]()~`>#+\-=|{}.!\\\\])/g, '\\$1');
};

const escapeCodeBlock = (text) => {
    return String(text).replace(/([\\`])/g, '\\$1');
};

module.exports = {
    escapeMdV2,
    escapeCodeBlock
};
