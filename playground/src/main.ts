import './style.css';
import { boot } from './app';

boot(document.getElementById('app')).catch((err) => {
  const app = document.getElementById('app');
  if (app) {
    app.innerHTML = '';
    const p = document.createElement('p');
    p.className = 'fatal';
    p.textContent = `The playground could not start: ${err instanceof Error ? err.message : String(err)}`;
    app.appendChild(p);
  }
  throw err;
});
