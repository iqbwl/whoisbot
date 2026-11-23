const axios = require('axios');

const httpGetJson = async (url, timeout = 10000) => {
    try {
        console.log(`Querying: ${url}`);
        const response = await axios.get(url, {
            timeout,
            headers: { 'Accept': 'application/rdap+json' },
            validateStatus: (status) => status >= 200 && status < 400
        });
        return [response.data, response.status, null];
    } catch (error) {
        console.error(`Error querying ${url}:`, error.message);
        if (error.response) {
            return [null, error.response.status, `HTTP ${error.response.status}`];
        }
        return [null, 0, error.message];
    }
};

module.exports = {
    httpGetJson
};
