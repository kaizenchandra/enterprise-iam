import http from 'k6/http';
import encoding from 'k6/encoding';
import {check} from 'k6';

export const options = {
    scenarios: {
        tokens: {
            executor: 'constant-arrival-rate',
            rate: Number(__ENV.RATE || 100),
            timeUnit: '1s',
            duration: __ENV.DURATION || '30s',
            preAllocatedVUs: 20,
            maxVUs: 200
        }
    }, thresholds: {http_req_failed: ['rate<0.01'], http_req_duration: ['p(99)<100']}
};
export default function () {
    const r = http.post(`${__ENV.ISSUER || 'http://localhost:9000'}/oauth2/token`, {
        grant_type: 'client_credentials',
        scope: 'orders.read'
    }, {
        headers: {Authorization: `Basic ${encoding.b64encode('order-service:' + __ENV.MACHINE_SECRET)}`},
        timeout: '5s'
    });
    check(r, {'token issued': r => r.status === 200});
}
