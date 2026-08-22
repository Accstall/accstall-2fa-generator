import { createTotp } from './totp.js';

document.addEventListener('alpine:init', () => {
  Alpine.data('accstallTotp', createTotp);
});
