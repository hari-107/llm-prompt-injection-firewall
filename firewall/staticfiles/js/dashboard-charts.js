/* Shared dashboard chart presentation. All data still comes from the scan API. */
window.FirewallCharts = (() => {
  Chart.defaults.color = '#a9bace';
  Chart.defaults.borderColor = '#263449';
  Chart.defaults.font.family = 'system-ui, sans-serif';
  Chart.defaults.responsive = true;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.animation = !matchMedia('(prefers-reduced-motion: reduce)').matches;
  const colors = {
    allow: '#59d9a0', sanitize: '#f6bb65', warn: '#9ca9d1', block: '#fc7887',
    safe: '#59d9a0', low: '#9ca9d1', medium: '#f6bb65', high: '#fc7887', critical: '#e95169',
  };
  const color = label => colors[String(label).toLowerCase()] || '#94a4b8';
  const label = value => value ? String(value).replaceAll('_', ' ') : 'Unknown';
  const axes = {
    x: { grid: { color: '#263449' }, ticks: { maxRotation: 0, autoSkip: true } },
    y: { beginAtZero: true, grid: { color: '#263449' }, ticks: { precision: 0 } },
  };
  function status(canvas, message) {
    if (!canvas) return;
    const text = document.createElement('p');
    text.className = 'chart-status';
    text.setAttribute('role', 'status');
    text.textContent = message;
    canvas.replaceWith(text);
  }
  function create(id, config) {
    const canvas = document.getElementById(id);
    if (!config.data.datasets.some(set => set.data.some(value => Number(value) > 0))) {
      status(canvas, 'No requests recorded for this chart yet.');
      return;
    }
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', config.data.labels.map((name, i) =>
      `${name}: ${config.data.datasets[0].data[i]}`).join(', '));
    return new Chart(canvas, config);
  }
  function unavailable() {
    document.querySelectorAll('.chart-frame canvas').forEach(canvas =>
      status(canvas, 'Analytics could not be loaded. Refresh to try again.'));
  }
  return { color, label, axes, create, unavailable };
})();
