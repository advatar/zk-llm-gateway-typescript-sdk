import { Redactor, RedactionMode } from '../src/index.js';

const redactor = new Redactor(RedactionMode.StablePerValue);
redactor.addCustomTerm('super-secret-project');

const input = 'Email me at alice@example.com about super-secret-project. My wallet is 0x0123456789abcdef0123456789abcdef01234567';
const res = redactor.redactText(input);

console.log('Redacted:', res.redacted);
console.log('Map:', res.map);
console.log('Rehydrated:', redactor.rehydrateText(res.redacted, res.map));
